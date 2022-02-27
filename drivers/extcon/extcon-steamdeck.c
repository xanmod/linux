
#include <linux/acpi.h>
#include <linux/platform_device.h>
#include <linux/extcon-provider.h>

#define ACPI_STEAMDECK_NOTIFY_STATUS	0x80

/* 0 - port connected, 1 -port disconnected */
#define ACPI_STEAMDECK_PORT_CONNECT	BIT(0)
/* 0 - Upstream Facing Port, 1 - Downdstream Facing Port */
#define ACPI_STEAMDECK_CUR_DATA_ROLE	BIT(3)
/*
 * Debouncing delay to allow negotiation process to settle. 2s value
 * was arrived at via trial and error.
 */
#define STEAMDECK_ROLE_SWITCH_DELAY	(msecs_to_jiffies(2000))

struct steamdeck_extcon {
	struct acpi_device *adev;
	struct delayed_work role_work;
	struct extcon_dev *edev;
	struct device *dev;
};

static int steamdeck_read_pdcs(struct steamdeck_extcon *sd, unsigned long long *pdcs)
{
	acpi_status status;

	status = acpi_evaluate_integer(sd->adev->handle, "PDCS", NULL, pdcs);
	if (ACPI_FAILURE(status)) {
		dev_err(sd->dev, "PDCS evaluation failed: %s\n",
			acpi_format_exception(status));
		return -EIO;
	}

	return 0;
}

static void steamdeck_usb_role_work(struct work_struct *work)
{
	struct steamdeck_extcon *sd =
		container_of(work, struct steamdeck_extcon, role_work.work);
	unsigned long long pdcs;
	bool usb_host;

	if (steamdeck_read_pdcs(sd, &pdcs))
		return;

	/*
	 * We only care about these two
	 */
	pdcs &= ACPI_STEAMDECK_PORT_CONNECT | ACPI_STEAMDECK_CUR_DATA_ROLE;

	/*
	 * For "connect" events our role is determined by a bit in
	 * PDCS, for "disconnect" we switch to being a gadget
	 * unconditionally. The thinking for the latter is we don't
	 * want to start acting as a USB host until we get
	 * confirmation from the firmware that we are a USB host
	 */
	usb_host = (pdcs & ACPI_STEAMDECK_PORT_CONNECT) ?
		pdcs & ACPI_STEAMDECK_CUR_DATA_ROLE : false;

	dev_dbg(sd->dev, "USB role is %s\n", usb_host ? "host" : "device");
	WARN_ON(extcon_set_state_sync(sd->edev, EXTCON_USB_HOST,
				      usb_host));

}

static void steamdeck_notify(acpi_handle handle, u32 event, void *context)
{
	struct device *dev = context;
	struct steamdeck_extcon *sd = dev_get_drvdata(dev);
	unsigned long long pdcs;
	unsigned long delay;

	switch (event) {
	case ACPI_STEAMDECK_NOTIFY_STATUS:
		if (steamdeck_read_pdcs(sd, &pdcs))
			return;
		/*
		 * We process "disconnect" events immediately and
		 * "connect" events with a delay to give the HW time
		 * to settle. For example attaching USB hub (at least
		 * for HW used for testing) will generate intermediary
		 * event with "host" bit not set, followed by the one
		 * that does have it set.
		 */
		delay = (pdcs & ACPI_STEAMDECK_PORT_CONNECT) ?
			STEAMDECK_ROLE_SWITCH_DELAY : 0;

		queue_delayed_work(system_long_wq, &sd->role_work, delay);
		break;
	default:
		dev_warn(dev, "Unsupported event [0x%x]\n", event);
	}
}

static void steamdeck_remove_notify_handler(void *data)
{
	struct steamdeck_extcon *sd = data;

	acpi_remove_notify_handler(sd->adev->handle, ACPI_DEVICE_NOTIFY,
				   steamdeck_notify);
	cancel_delayed_work_sync(&sd->role_work);
}

static const unsigned int steamdeck_extcon_cable[] = {
	EXTCON_USB,
	EXTCON_USB_HOST,
	EXTCON_CHG_USB_SDP,
	EXTCON_CHG_USB_CDP,
	EXTCON_CHG_USB_DCP,
	EXTCON_CHG_USB_ACA,
	EXTCON_NONE,
};

static int steamdeck_extcon_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct steamdeck_extcon *sd;
	acpi_status status;
	int ret;

	sd = devm_kzalloc(dev, sizeof(*sd), GFP_KERNEL);
	if (!sd)
		return -ENOMEM;

	INIT_DELAYED_WORK(&sd->role_work, steamdeck_usb_role_work);
	platform_set_drvdata(pdev, sd);
	sd->adev = ACPI_COMPANION(dev->parent);
	sd->dev  = dev;
	sd->edev = devm_extcon_dev_allocate(dev, steamdeck_extcon_cable);
	if (IS_ERR(sd->edev))
		return PTR_ERR(sd->edev);

	ret = devm_extcon_dev_register(dev, sd->edev);
	if (ret < 0) {
		dev_err(dev, "Failed to register extcon device: %d\n", ret);
		return ret;
	}

	/*
	 * Set initial role value
	 */
	queue_delayed_work(system_long_wq, &sd->role_work, 0);
	flush_delayed_work(&sd->role_work);

	status = acpi_install_notify_handler(sd->adev->handle,
					     ACPI_DEVICE_NOTIFY,
					     steamdeck_notify,
					     dev);
	if (ACPI_FAILURE(status)) {
		dev_err(dev, "Error installing ACPI notify handler\n");
		return -EIO;
	}

	ret = devm_add_action_or_reset(dev, steamdeck_remove_notify_handler,
				       sd);
	return ret;
}

static const struct platform_device_id steamdeck_extcon_id_table[] = {
	{ .name = "steamdeck-extcon" },
	{}
};
MODULE_DEVICE_TABLE(platform, steamdeck_extcon_id_table);

static struct platform_driver steamdeck_extcon_driver = {
	.probe = steamdeck_extcon_probe,
	.driver = {
		.name = "steamdeck-extcon",
	},
	.id_table = steamdeck_extcon_id_table,
};
module_platform_driver(steamdeck_extcon_driver);

MODULE_AUTHOR("Andrey Smirnov <andrew.smirnov@gmail.com>");
MODULE_DESCRIPTION("Steam Deck extcon driver");
MODULE_LICENSE("GPL");
