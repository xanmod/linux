// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Stadia controller rumble support.
 *
 * Copyright 2023 Google LLC
 */

#include <linux/hid.h>
#include <linux/input.h>
#include <linux/slab.h>
#include <linux/module.h>

#include "hid-ids.h"

#define STADIA_FF_REPORT_ID 5

struct stadiaff_device {
	struct hid_device *hid;
	struct hid_report *report;
	struct work_struct work;
};

static void stadiaff_work(struct work_struct *work)
{
	struct stadiaff_device *stadiaff =
		container_of(work, struct stadiaff_device, work);

	hid_hw_request(stadiaff->hid, stadiaff->report, HID_REQ_SET_REPORT);
}

static int stadiaff_play(struct input_dev *dev, void *data,
			 struct ff_effect *effect)
{
	struct hid_device *hid = input_get_drvdata(dev);
	struct stadiaff_device *stadiaff = hid_get_drvdata(hid);
	struct hid_field *rumble_field = stadiaff->report->field[0];

	rumble_field->value[0] = effect->u.rumble.strong_magnitude;
	rumble_field->value[1] = effect->u.rumble.weak_magnitude;

	schedule_work(&stadiaff->work);

	return 0;
}

static int stadiaff_init(struct hid_device *hid)
{
	struct stadiaff_device *stadiaff;
	struct hid_report *report;
	struct hid_input *hidinput;
	struct input_dev *dev;
	int error;

	if (list_empty(&hid->inputs)) {
		hid_err(hid, "no inputs found\n");
		return -ENODEV;
	}
	hidinput = list_entry(hid->inputs.next, struct hid_input, list);
	dev = hidinput->input;

	report = hid_validate_values(hid, HID_OUTPUT_REPORT,
				     STADIA_FF_REPORT_ID, 0, 2);
	if (!report)
		return -ENODEV;

	stadiaff = devm_kzalloc(&hid->dev, sizeof(struct stadiaff_device),
				GFP_KERNEL);
	if (!stadiaff)
		return -ENOMEM;

	hid_set_drvdata(hid, stadiaff);

	input_set_capability(dev, EV_FF, FF_RUMBLE);

	error = input_ff_create_memless(dev, NULL, stadiaff_play);
	if (error)
		return error;

	stadiaff->hid = hid;
	stadiaff->report = report;
	INIT_WORK(&stadiaff->work, stadiaff_work);

	hid_info(hid, "Force Feedback for Google Stadia controller\n");

	return 0;
}

static int stadia_probe(struct hid_device *hdev, const struct hid_device_id *id)
{
	int ret;

	ret = hid_parse(hdev);
	if (ret) {
		hid_err(hdev, "parse failed\n");
		return ret;
	}

	ret = hid_hw_start(hdev, HID_CONNECT_DEFAULT & ~HID_CONNECT_FF);
	if (ret) {
		hid_err(hdev, "hw start failed\n");
		return ret;
	}

	stadiaff_init(hdev);

	return 0;
}

static void stadia_remove(struct hid_device *hid)
{
	struct stadiaff_device *stadiaff = hid_get_drvdata(hid);

	cancel_work_sync(&stadiaff->work);
	hid_hw_stop(hid);
}

static const struct hid_device_id stadia_devices[] = {
	{ HID_USB_DEVICE(USB_VENDOR_ID_GOOGLE, USB_DEVICE_ID_GOOGLE_STADIA) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_GOOGLE, USB_DEVICE_ID_GOOGLE_STADIA) },
	{ }
};
MODULE_DEVICE_TABLE(hid, stadia_devices);

static struct hid_driver stadia_driver = {
	.name = "stadia",
	.id_table = stadia_devices,
	.probe = stadia_probe,
	.remove = stadia_remove,
};
module_hid_driver(stadia_driver);

MODULE_LICENSE("GPL");
