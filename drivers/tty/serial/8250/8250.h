/* SPDX-License-Identifier: GPL-2.0+ */
/*
 *  Driver for 8250/16550-type serial ports
 *
 *  Based on drivers/char/serial.c, by Linus Torvalds, Theodore Ts'o.
 *
 *  Copyright (C) 2001 Russell King.
 */

#include <linux/bits.h>
#include <linux/serial_8250.h>
#include <linux/serial_reg.h>
#include <linux/dmaengine.h>

#include "../serial_mctrl_gpio.h"

struct uart_8250_dma {
	int (*tx_dma)(struct uart_8250_port *p);
	int (*rx_dma)(struct uart_8250_port *p);
	void (*prepare_tx_dma)(struct uart_8250_port *p);
	void (*prepare_rx_dma)(struct uart_8250_port *p);

	/* Filter function */
	dma_filter_fn		fn;
	/* Parameter to the filter function */
	void			*rx_param;
	void			*tx_param;

	struct dma_slave_config	rxconf;
	struct dma_slave_config	txconf;

	struct dma_chan		*rxchan;
	struct dma_chan		*txchan;

	/* Device address base for DMA operations */
	phys_addr_t		rx_dma_addr;
	phys_addr_t		tx_dma_addr;

	/* DMA address of the buffer in memory */
	dma_addr_t		rx_addr;
	dma_addr_t		tx_addr;

	dma_cookie_t		rx_cookie;
	dma_cookie_t		tx_cookie;

	void			*rx_buf;

	size_t			rx_size;
	size_t			tx_size;

	unsigned char		tx_running;
	unsigned char		tx_err;
	unsigned char		rx_running;
};

struct old_serial_port {
	unsigned int uart;
	unsigned int baud_base;
	unsigned int port;
	unsigned int irq;
	upf_t        flags;
	unsigned char io_type;
	unsigned char __iomem *iomem_base;
	unsigned short iomem_reg_shift;
};

struct serial8250_config {
	const char	*name;
	unsigned short	fifo_size;
	unsigned short	tx_loadsz;
	unsigned char	fcr;
	unsigned char	rxtrig_bytes[UART_FCR_R_TRIG_MAX_STATE];
	unsigned int	flags;
};

#define UART_CAP_FIFO	BIT(8)	/* UART has FIFO */
#define UART_CAP_EFR	BIT(9)	/* UART has EFR */
#define UART_CAP_SLEEP	BIT(10)	/* UART has IER sleep */
#define UART_CAP_AFE	BIT(11)	/* MCR-based hw flow control */
#define UART_CAP_UUE	BIT(12)	/* UART needs IER bit 6 set (Xscale) */
#define UART_CAP_RTOIE	BIT(13)	/* UART needs IER bit 4 set (Xscale, Tegra) */
#define UART_CAP_HFIFO	BIT(14)	/* UART has a "hidden" FIFO */
#define UART_CAP_RPM	BIT(15)	/* Runtime PM is active while idle */
#define UART_CAP_IRDA	BIT(16)	/* UART supports IrDA line discipline */
#define UART_CAP_MINI	BIT(17)	/* Mini UART on BCM283X family lacks:
					 * STOP PARITY EPAR SPAR WLEN5 WLEN6
					 */
#define UART_CAP_NOTEMT	BIT(18)	/* UART without interrupt on TEMT available */

#define UART_BUG_QUOT	BIT(0)	/* UART has buggy quot LSB */
#define UART_BUG_TXEN	BIT(1)	/* UART has buggy TX IIR status */
#define UART_BUG_NOMSR	BIT(2)	/* UART has buggy MSR status bits (Au1x00) */
#define UART_BUG_THRE	BIT(3)	/* UART has buggy THRE reassertion */
#define UART_BUG_TXRACE	BIT(5)	/* UART Tx fails to set remote DR */


#ifdef CONFIG_SERIAL_8250_SHARE_IRQ
#define SERIAL8250_SHARE_IRQS 1
#else
#define SERIAL8250_SHARE_IRQS 0
#endif

#define SERIAL8250_PORT_FLAGS(_base, _irq, _flags)		\
	{							\
		.iobase		= _base,			\
		.irq		= _irq,				\
		.uartclk	= 1843200,			\
		.iotype		= UPIO_PORT,			\
		.flags		= UPF_BOOT_AUTOCONF | (_flags),	\
	}

#define SERIAL8250_PORT(_base, _irq) SERIAL8250_PORT_FLAGS(_base, _irq, 0)


static inline int serial_in(struct uart_8250_port *up, int offset)
{
	return up->port.serial_in(&up->port, offset);
}

static inline void serial_out(struct uart_8250_port *up, int offset, int value)
{
	up->port.serial_out(&up->port, offset, value);
}

/**
 *	serial_lsr_in - Read LSR register and preserve flags across reads
 *	@up:	uart 8250 port
 *
 *	Read LSR register and handle saving non-preserved flags across reads.
 *	The flags that are not preserved across reads are stored into
 *	up->lsr_saved_flags.
 *
 *	Returns LSR value or'ed with the preserved flags (if any).
 */
static inline u16 serial_lsr_in(struct uart_8250_port *up)
{
	u16 lsr = up->lsr_saved_flags;

	lsr |= serial_in(up, UART_LSR);
	up->lsr_saved_flags = lsr & up->lsr_save_mask;

	return lsr;
}

/*
 * For the 16C950
 */
static void serial_icr_write(struct uart_8250_port *up, int offset, int value)
{
	serial_out(up, UART_SCR, offset);
	serial_out(up, UART_ICR, value);
}

static unsigned int __maybe_unused serial_icr_read(struct uart_8250_port *up,
						   int offset)
{
	unsigned int value;

	serial_icr_write(up, UART_ACR, up->acr | UART_ACR_ICRRD);
	serial_out(up, UART_SCR, offset);
	value = serial_in(up, UART_ICR);
	serial_icr_write(up, UART_ACR, up->acr);

	return value;
}

void serial8250_clear_and_reinit_fifos(struct uart_8250_port *p);

static inline u32 serial_dl_read(struct uart_8250_port *up)
{
	return up->dl_read(up);
}

static inline void serial_dl_write(struct uart_8250_port *up, u32 value)
{
	up->dl_write(up, value);
}

static inline bool serial8250_is_console(struct uart_port *port)
{
	return uart_console(port) && !hlist_unhashed_lockless(&port->cons->node);
}

/**
 * serial8250_init_wctxt - Initialize a write context for
 *	non-console-printing usage
 * @wctxt:	The write context to initialize
 * @cons:	The console to assign to the write context
 *
 * In order to mark an unsafe region, drivers must acquire the console. This
 * requires providing an initialized write context (even if that driver will
 * not be doing any printing).
 *
 * This function should not be used for console printing contexts.
 */
static inline void serial8250_init_wctxt(struct cons_write_context *wctxt,
					 struct console *cons)
{
	struct cons_context *ctxt = &ACCESS_PRIVATE(wctxt, ctxt);

	memset(wctxt, 0, sizeof(*wctxt));
	ctxt->console = cons;
	ctxt->prio = CONS_PRIO_NORMAL;
}

/**
 * __serial8250_console_acquire - Acquire a console for
 *	non-console-printing usage
 * @wctxt:	An uninitialized write context to use for acquiring
 * @cons:	The console to assign to the write context
 *
 * The caller is holding the port->lock.
 * The caller is holding the console_srcu_read_lock.
 *
 * This function should not be used for console printing contexts.
 */
static inline void __serial8250_console_acquire(struct cons_write_context *wctxt,
						struct console *cons)
{
	for (;;) {
		serial8250_init_wctxt(wctxt, cons);
		if (console_try_acquire(wctxt))
			break;
		cpu_relax();
	}
}

/**
 * serial8250_enter_unsafe - Mark the beginning of an unsafe region for
 *		non-console-printing usage
 * @up:	The port that is entering the unsafe state
 *
 * The caller should ensure @up is a console before calling this function.
 *
 * The caller is holding the port->lock.
 * This function takes the console_srcu_read_lock and becomes owner of the
 * console associated with @up.
 *
 * This function should not be used for console printing contexts.
 */
static inline void serial8250_enter_unsafe(struct uart_8250_port *up)
{
	struct uart_port *port = &up->port;

	lockdep_assert_held_once(&port->lock);

	for (;;) {
		up->cookie = console_srcu_read_lock();

		__serial8250_console_acquire(&up->wctxt, port->cons);

		if (console_enter_unsafe(&up->wctxt))
			break;

		console_srcu_read_unlock(up->cookie);
		cpu_relax();
	}
}

/**
 * serial8250_exit_unsafe - Mark the end of an unsafe region for
 *		non-console-printing usage
 * @up:	The port that is exiting the unsafe state
 *
 * The caller is holding the port->lock.
 * This function releases ownership of the console associated with @up and
 * releases the console_srcu_read_lock.
 *
 * This function should not be used for console printing contexts.
 */
static inline void serial8250_exit_unsafe(struct uart_8250_port *up)
{
	struct uart_port *port = &up->port;

	lockdep_assert_held_once(&port->lock);

	if (console_exit_unsafe(&up->wctxt))
		console_release(&up->wctxt);

	console_srcu_read_unlock(up->cookie);
}

/**
 * serial8250_in_IER - Read the IER register for
 *		non-console-printing usage
 * @up:	The port to work on
 *
 * Returns:	The value read from IER
 *
 * The caller is holding the port->lock.
 *
 * This is the top-level function for non-console-printing contexts to
 * read the IER register. The caller does not need to care if @up is a
 * console before calling this function.
 *
 * This function should not be used for printing contexts.
 */
static inline int serial8250_in_IER(struct uart_8250_port *up)
{
	struct uart_port *port = &up->port;
	bool is_console;
	int ier;

	is_console = serial8250_is_console(port);

	if (is_console)
		serial8250_enter_unsafe(up);

	ier = serial_in(up, UART_IER);

	if (is_console)
		serial8250_exit_unsafe(up);

	return ier;
}

/**
 * __serial8250_set_IER - Directly write to the IER register
 * @up:		The port to work on
 * @wctxt:	The current write context
 * @ier:	The value to write
 *
 * Returns:	True if IER was written to. False otherwise
 *
 * The caller is holding the port->lock.
 * The caller is holding the console_srcu_read_unlock.
 * The caller is the owner of the console associated with @up.
 *
 * This function should only be directly called within console printing
 * contexts. Other contexts should use serial8250_set_IER().
 */
static inline bool __serial8250_set_IER(struct uart_8250_port *up,
					struct cons_write_context *wctxt,
					int ier)
{
	if (wctxt && !console_can_proceed(wctxt))
		return false;
	serial_out(up, UART_IER, ier);
	return true;
}

/**
 * serial8250_set_IER - Write a new value to the IER register for
 *	non-console-printing usage
 * @up:		The port to work on
 * @ier:	The value to write
 *
 * The caller is holding the port->lock.
 *
 * This is the top-level function for non-console-printing contexts to
 * write to the IER register. The caller does not need to care if @up is a
 * console before calling this function.
 *
 * This function should not be used for printing contexts.
 */
static inline void serial8250_set_IER(struct uart_8250_port *up, int ier)
{
	struct uart_port *port = &up->port;
	bool is_console;

	is_console = serial8250_is_console(port);

	if (is_console) {
		serial8250_enter_unsafe(up);
		while (!__serial8250_set_IER(up, &up->wctxt, ier)) {
			console_srcu_read_unlock(up->cookie);
			console_enter_unsafe(&up->wctxt);
		}
		serial8250_exit_unsafe(up);
	} else {
		__serial8250_set_IER(up, NULL, ier);
	}
}

/**
 * __serial8250_clear_IER - Directly clear the IER register
 * @up:		The port to work on
 * @wctxt:	The current write context
 * @prior:	Gets set to the previous value of IER
 *
 * Returns:	True if IER was cleared and @prior points to the previous
 *		value of IER. False otherwise and @prior is invalid
 *
 * The caller is holding the port->lock.
 * The caller is holding the console_srcu_read_unlock.
 * The caller is the owner of the console associated with @up.
 *
 * This function should only be directly called within console printing
 * contexts. Other contexts should use serial8250_clear_IER().
 */
static inline bool __serial8250_clear_IER(struct uart_8250_port *up,
					  struct cons_write_context *wctxt,
					  int *prior)
{
	unsigned int clearval = 0;

	if (up->capabilities & UART_CAP_UUE)
		clearval = UART_IER_UUE;

	*prior = serial_in(up, UART_IER);
	if (wctxt && !console_can_proceed(wctxt))
		return false;
	serial_out(up, UART_IER, clearval);
	return true;
}

/**
 * serial8250_clear_IER - Clear the IER register for
 *		non-console-printing usage
 * @up:	The port to work on
 *
 * Returns:	The previous value of IER
 *
 * The caller is holding the port->lock.
 *
 * This is the top-level function for non-console-printing contexts to
 * clear the IER register. The caller does not need to care if @up is a
 * console before calling this function.
 *
 * This function should not be used for printing contexts.
 */
static inline int serial8250_clear_IER(struct uart_8250_port *up)
{
	struct uart_port *port = &up->port;
	bool is_console;
	int prior;

	is_console = serial8250_is_console(port);

	if (is_console) {
		serial8250_enter_unsafe(up);
		while (!__serial8250_clear_IER(up, &up->wctxt, &prior)) {
			console_srcu_read_unlock(up->cookie);
			console_enter_unsafe(&up->wctxt);
		}
		serial8250_exit_unsafe(up);
	} else {
		__serial8250_clear_IER(up, NULL, &prior);
	}

	return prior;
}

static inline bool serial8250_set_THRI(struct uart_8250_port *up)
{
	/* Port locked to synchronize UART_IER access against the console. */
	lockdep_assert_held_once(&up->port.lock);

	if (up->ier & UART_IER_THRI)
		return false;
	up->ier |= UART_IER_THRI;
	serial8250_set_IER(up, up->ier);
	return true;
}

static inline bool serial8250_clear_THRI(struct uart_8250_port *up)
{
	/* Port locked to synchronize UART_IER access against the console. */
	lockdep_assert_held_once(&up->port.lock);

	if (!(up->ier & UART_IER_THRI))
		return false;
	up->ier &= ~UART_IER_THRI;
	serial8250_set_IER(up, up->ier);
	return true;
}

struct uart_8250_port *serial8250_get_port(int line);

void serial8250_rpm_get(struct uart_8250_port *p);
void serial8250_rpm_put(struct uart_8250_port *p);

void serial8250_rpm_get_tx(struct uart_8250_port *p);
void serial8250_rpm_put_tx(struct uart_8250_port *p);

int serial8250_em485_config(struct uart_port *port, struct ktermios *termios,
			    struct serial_rs485 *rs485);
void serial8250_em485_start_tx(struct uart_8250_port *p);
void serial8250_em485_stop_tx(struct uart_8250_port *p);
void serial8250_em485_destroy(struct uart_8250_port *p);
extern struct serial_rs485 serial8250_em485_supported;

/* MCR <-> TIOCM conversion */
static inline int serial8250_TIOCM_to_MCR(int tiocm)
{
	int mcr = 0;

	if (tiocm & TIOCM_RTS)
		mcr |= UART_MCR_RTS;
	if (tiocm & TIOCM_DTR)
		mcr |= UART_MCR_DTR;
	if (tiocm & TIOCM_OUT1)
		mcr |= UART_MCR_OUT1;
	if (tiocm & TIOCM_OUT2)
		mcr |= UART_MCR_OUT2;
	if (tiocm & TIOCM_LOOP)
		mcr |= UART_MCR_LOOP;

	return mcr;
}

static inline int serial8250_MCR_to_TIOCM(int mcr)
{
	int tiocm = 0;

	if (mcr & UART_MCR_RTS)
		tiocm |= TIOCM_RTS;
	if (mcr & UART_MCR_DTR)
		tiocm |= TIOCM_DTR;
	if (mcr & UART_MCR_OUT1)
		tiocm |= TIOCM_OUT1;
	if (mcr & UART_MCR_OUT2)
		tiocm |= TIOCM_OUT2;
	if (mcr & UART_MCR_LOOP)
		tiocm |= TIOCM_LOOP;

	return tiocm;
}

/* MSR <-> TIOCM conversion */
static inline int serial8250_MSR_to_TIOCM(int msr)
{
	int tiocm = 0;

	if (msr & UART_MSR_DCD)
		tiocm |= TIOCM_CAR;
	if (msr & UART_MSR_RI)
		tiocm |= TIOCM_RNG;
	if (msr & UART_MSR_DSR)
		tiocm |= TIOCM_DSR;
	if (msr & UART_MSR_CTS)
		tiocm |= TIOCM_CTS;

	return tiocm;
}

static inline void serial8250_out_MCR(struct uart_8250_port *up, int value)
{
	serial_out(up, UART_MCR, value);

	if (up->gpios)
		mctrl_gpio_set(up->gpios, serial8250_MCR_to_TIOCM(value));
}

static inline int serial8250_in_MCR(struct uart_8250_port *up)
{
	int mctrl;

	mctrl = serial_in(up, UART_MCR);

	if (up->gpios) {
		unsigned int mctrl_gpio = 0;

		mctrl_gpio = mctrl_gpio_get_outputs(up->gpios, &mctrl_gpio);
		mctrl |= serial8250_TIOCM_to_MCR(mctrl_gpio);
	}

	return mctrl;
}

bool alpha_jensen(void);
void alpha_jensen_set_mctrl(struct uart_port *port, unsigned int mctrl);

#ifdef CONFIG_SERIAL_8250_PNP
int serial8250_pnp_init(void);
void serial8250_pnp_exit(void);
#else
static inline int serial8250_pnp_init(void) { return 0; }
static inline void serial8250_pnp_exit(void) { }
#endif

#ifdef CONFIG_SERIAL_8250_FINTEK
int fintek_8250_probe(struct uart_8250_port *uart);
#else
static inline int fintek_8250_probe(struct uart_8250_port *uart) { return 0; }
#endif

#ifdef CONFIG_ARCH_OMAP1
#include <linux/soc/ti/omap1-soc.h>
static inline int is_omap1_8250(struct uart_8250_port *pt)
{
	int res;

	switch (pt->port.mapbase) {
	case OMAP1_UART1_BASE:
	case OMAP1_UART2_BASE:
	case OMAP1_UART3_BASE:
		res = 1;
		break;
	default:
		res = 0;
		break;
	}

	return res;
}

static inline int is_omap1510_8250(struct uart_8250_port *pt)
{
	if (!cpu_is_omap1510())
		return 0;

	return is_omap1_8250(pt);
}
#else
static inline int is_omap1_8250(struct uart_8250_port *pt)
{
	return 0;
}
static inline int is_omap1510_8250(struct uart_8250_port *pt)
{
	return 0;
}
#endif

#ifdef CONFIG_SERIAL_8250_DMA
extern int serial8250_tx_dma(struct uart_8250_port *);
extern int serial8250_rx_dma(struct uart_8250_port *);
extern void serial8250_rx_dma_flush(struct uart_8250_port *);
extern int serial8250_request_dma(struct uart_8250_port *);
extern void serial8250_release_dma(struct uart_8250_port *);

static inline void serial8250_do_prepare_tx_dma(struct uart_8250_port *p)
{
	struct uart_8250_dma *dma = p->dma;

	if (dma->prepare_tx_dma)
		dma->prepare_tx_dma(p);
}

static inline void serial8250_do_prepare_rx_dma(struct uart_8250_port *p)
{
	struct uart_8250_dma *dma = p->dma;

	if (dma->prepare_rx_dma)
		dma->prepare_rx_dma(p);
}

static inline bool serial8250_tx_dma_running(struct uart_8250_port *p)
{
	struct uart_8250_dma *dma = p->dma;

	return dma && dma->tx_running;
}
#else
static inline int serial8250_tx_dma(struct uart_8250_port *p)
{
	return -1;
}
static inline int serial8250_rx_dma(struct uart_8250_port *p)
{
	return -1;
}
static inline void serial8250_rx_dma_flush(struct uart_8250_port *p) { }
static inline int serial8250_request_dma(struct uart_8250_port *p)
{
	return -1;
}
static inline void serial8250_release_dma(struct uart_8250_port *p) { }

static inline bool serial8250_tx_dma_running(struct uart_8250_port *p)
{
	return false;
}
#endif

static inline int ns16550a_goto_highspeed(struct uart_8250_port *up)
{
	unsigned char status;

	status = serial_in(up, 0x04); /* EXCR2 */
#define PRESL(x) ((x) & 0x30)
	if (PRESL(status) == 0x10) {
		/* already in high speed mode */
		return 0;
	} else {
		status &= ~0xB0; /* Disable LOCK, mask out PRESL[01] */
		status |= 0x10;  /* 1.625 divisor for baud_base --> 921600 */
		serial_out(up, 0x04, status);
	}
	return 1;
}

static inline int serial_index(struct uart_port *port)
{
	return port->minor - 64;
}
