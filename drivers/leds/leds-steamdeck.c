// SPDX-License-Identifier: GPL-2.0+

/*
 * Steam Deck EC MFD LED cell driver
 *
 * Copyright (C) 2021-2022 Valve Corporation
 *
 */

#include <linux/acpi.h>
#include <linux/leds.h>
#include <linux/platform_device.h>

struct steamdeck_led {
	struct acpi_device *adev;
	struct led_classdev cdev;
};

static int steamdeck_leds_brightness_set(struct led_classdev *cdev,
					 enum led_brightness value)
{
	struct steamdeck_led *sd = container_of(cdev, struct steamdeck_led,
						cdev);

	if (ACPI_FAILURE(acpi_execute_simple_method(sd->adev->handle,
						    "CHBV", value)))
		return -EIO;

	return 0;
}

static int steamdeck_leds_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct steamdeck_led *sd;
	int ret;

	sd = devm_kzalloc(dev, sizeof(*sd), GFP_KERNEL);
	if (!sd)
		return -ENOMEM;

	sd->adev = ACPI_COMPANION(dev->parent);

	sd->cdev.name = "status:white";
	sd->cdev.brightness_set_blocking = steamdeck_leds_brightness_set;
	sd->cdev.max_brightness = 100;

	ret = devm_led_classdev_register(dev, &sd->cdev);
	if (ret) {
		dev_err(dev, "Failed to register LEDs device: %d\n", ret);
		return ret;
	}

	return 0;
}

static const struct platform_device_id steamdeck_leds_id_table[] = {
	{ .name = "steamdeck-leds" },
	{}
};
MODULE_DEVICE_TABLE(platform, steamdeck_leds_id_table);

static struct platform_driver steamdeck_leds_driver = {
	.probe = steamdeck_leds_probe,
	.driver = {
		.name = "steamdeck-leds",
	},
	.id_table = steamdeck_leds_id_table,
};
module_platform_driver(steamdeck_leds_driver);

MODULE_AUTHOR("Andrey Smirnov <andrew.smirnov@gmail.com>");
MODULE_DESCRIPTION("Steam Deck LEDs driver");
MODULE_LICENSE("GPL");
