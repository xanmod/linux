#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

TCID="test.sh"

KSFT_PASS=0
KSFT_FAIL=1
KSFT_SKIP=4

errno=$KSFT_PASS

check_root()
{
	local uid=$(id -u)
	if [ $uid -ne 0 ]; then
		echo $TCID: must be run as root >&2
		exit $KSFT_SKIP
	fi
}

tmp_files_setup()
{
	DMESG=$(mktemp --tmpdir -t brute-dmesg-XXXXXX)
}

tmp_files_cleanup()
{
	rm -f "$DMESG"
}

save_dmesg()
{
	dmesg > "$DMESG"
}

count_attack_matches()
{
	dmesg | comm --nocheck-order -13 "$DMESG" - | \
		grep "brute: fork brute force attack detected" | wc -l
}

assert_equal()
{
	local val1=$1
	local val2=$2

	if [ $val1 -eq $val2 ]; then
		echo "$TCID: $message [PASS]"
	else
		echo "$TCID: $message [FAIL]"
		errno=$KSFT_FAIL
	fi
}

test_fork_user()
{
	COUNTER=20

	save_dmesg
	./test -m crash -c fork -s user -n $COUNTER
	count=$(count_attack_matches)

	message="fork attack (user signals, no bounds crossed)"
	assert_equal $count 0
}

test_fork_kernel()
{
	save_dmesg
	./test -m crash -c fork -s kernel -n $COUNTER
	count=$(count_attack_matches)

	message="fork attack (kernel signals, no bounds crossed)"
	assert_equal $count 0
}

test_exec_user()
{
	save_dmesg
	./test -m crash -c exec -s user -n $COUNTER
	count=$(count_attack_matches)

	message="exec attack (user signals, no bounds crossed)"
	assert_equal $count 0
}

test_exec_kernel()
{
	save_dmesg
	./test -m crash -c exec -s kernel -n $COUNTER
	count=$(count_attack_matches)

	message="exec attack (kernel signals, no bounds crossed)"
	assert_equal $count 0
}

assert_not_equal()
{
	local val1=$1
	local val2=$2

	if [ $val1 -ne $val2 ]; then
		echo $TCID: $message [PASS]
	else
		echo $TCID: $message [FAIL]
		errno=$KSFT_FAIL
	fi
}

remove_xattr()
{
	./rmxattr test >/dev/null 2>&1
}

test_fork_kernel_setuid()
{
	save_dmesg
	chmod u+s test
	./test -m crash -c fork -s kernel -n $COUNTER
	chmod u-s test
	count=$(count_attack_matches)

	message="fork attack (kernel signals, setuid binary)"
	assert_not_equal $count 0
	remove_xattr
}

test_exec_kernel_setuid()
{
	save_dmesg
	chmod u+s test
	./test -m crash -c exec -s kernel -n $COUNTER
	chmod u-s test
	count=$(count_attack_matches)

	message="exec attack (kernel signals, setuid binary)"
	assert_not_equal $count 0
	remove_xattr
}

test_fork_kernel_change_priv()
{
	save_dmesg
	./test -m crash -c fork -s kernel -n $COUNTER -C
	count=$(count_attack_matches)

	message="fork attack (kernel signals, change privileges)"
	assert_not_equal $count 0
	remove_xattr
}

test_exec_kernel_change_priv()
{
	save_dmesg
	./test -m crash -c exec -s kernel -n $COUNTER -C
	count=$(count_attack_matches)

	message="exec attack (kernel signals, change privileges)"
	assert_not_equal $count 0
	remove_xattr
}

network_ns_setup()
{
	local vnet_name=$1
	local veth_name=$2
	local ip_src=$3
	local ip_dst=$4

	ip netns add $vnet_name
	ip link set $veth_name netns $vnet_name
	ip -n $vnet_name addr add $ip_src/24 dev $veth_name
	ip -n $vnet_name link set $veth_name up
	ip -n $vnet_name route add $ip_dst/24 dev $veth_name
}

network_setup()
{
	VETH0_NAME=veth0
	VNET0_NAME=vnet0
	VNET0_IP=10.0.1.0
	VETH1_NAME=veth1
	VNET1_NAME=vnet1
	VNET1_IP=10.0.2.0

	ip link add $VETH0_NAME type veth peer name $VETH1_NAME
	network_ns_setup $VNET0_NAME $VETH0_NAME $VNET0_IP $VNET1_IP
	network_ns_setup $VNET1_NAME $VETH1_NAME $VNET1_IP $VNET0_IP
}

test_fork_kernel_network_to_local()
{
	INADDR_ANY=0.0.0.0
	PORT=65535
	TIMEOUT=5

	save_dmesg
	ip netns exec $VNET0_NAME ./test -m server_crash -a $INADDR_ANY \
		-p $PORT -t $TIMEOUT -c fork -s kernel -n $COUNTER &
	sleep 1
	ip netns exec $VNET1_NAME ./test -m client -a $VNET0_IP -p $PORT \
		-t $TIMEOUT
	sleep 1
	count=$(count_attack_matches)

	message="fork attack (kernel signals, network to local)"
	assert_not_equal $count 0
	remove_xattr
}

test_exec_kernel_network_to_local()
{
	save_dmesg
	ip netns exec $VNET0_NAME ./test -m server_crash -a $INADDR_ANY \
		-p $PORT -t $TIMEOUT -c exec -s kernel -n $COUNTER &
	sleep 1
	ip netns exec $VNET1_NAME ./test -m client -a $VNET0_IP -p $PORT \
		-t $TIMEOUT
	sleep 1
	count=$(count_attack_matches)

	message="exec attack (kernel signals, network to local)"
	assert_not_equal $count 0
	remove_xattr
}

network_cleanup()
{
	ip netns del $VNET0_NAME >/dev/null 2>&1
	ip netns del $VNET1_NAME >/dev/null 2>&1
	ip link delete $VETH0_NAME >/dev/null 2>&1
	ip link delete $VETH1_NAME >/dev/null 2>&1
}

test_waitid()
{
	./exec test -m crash -c fork -s kernel -n $COUNTER -C
	local rc=$?

	message="notification to userspace via waitid system call"
	assert_equal $rc 0
	remove_xattr
}

cleanup()
{
        network_cleanup
	tmp_files_cleanup
	chmod u-s test
	remove_xattr
}
trap cleanup EXIT

check_root
tmp_files_setup
test_fork_user
test_fork_kernel
test_exec_user
test_exec_kernel
test_fork_kernel_setuid
test_exec_kernel_setuid
test_fork_kernel_change_priv
test_exec_kernel_change_priv
network_setup
test_fork_kernel_network_to_local
test_exec_kernel_network_to_local
network_cleanup
test_waitid
exit $errno
