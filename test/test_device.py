#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from r2flutch.device import get_usb_device, list_applications, spawn_r2frida_process, kill_process


class TestGetUsbDevice:

    @patch("r2flutch.device.frida")
    def test_returns_first_usb_device(self, mock_frida):
        usb_dev = MagicMock()
        usb_dev.type = "usb"
        non_usb_dev = MagicMock()
        non_usb_dev.type = "local"

        mock_dm = MagicMock()
        mock_frida.get_device_manager.return_value = mock_dm
        mock_dm.enumerate_devices.return_value = [non_usb_dev, usb_dev]

        result = get_usb_device()
        assert result is usb_dev
        mock_dm.off.assert_called_once()

    @patch("r2flutch.device.frida")
    def test_waits_when_no_usb_device_then_finds_one(self, mock_frida):
        usb_dev = MagicMock()
        usb_dev.type = "usb"

        mock_dm = MagicMock()
        mock_frida.get_device_manager.return_value = mock_dm
        # First call: no USB devices; second call: USB device present
        mock_dm.enumerate_devices.side_effect = [[], [usb_dev]]

        # The changed event is set by the on_changed callback; simulate it
        def fake_on(event_name, callback):
            # immediately trigger the callback so changed.wait() proceeds
            callback()

        mock_dm.on.side_effect = fake_on

        result = get_usb_device()
        assert result is usb_dev


class TestListApplications:

    @patch("r2flutch.device.print_console")
    def test_lists_applications(self, mock_print):
        mock_device = MagicMock()
        app1 = MagicMock()
        app1.identifier = "com.example.app1"
        app1.name = "App One"
        app2 = MagicMock()
        app2.identifier = "com.example.app2"
        app2.name = "App Two"
        mock_device.enumerate_applications.return_value = [app2, app1]

        list_applications(mock_device)

        lines = [c[0][0] for c in mock_print.call_args_list]
        # Header and separator
        assert "Bundle Identifier" in lines[0]
        assert "Name" in lines[0]
        # Apps are sorted by identifier
        assert "com.example.app1" in lines[2]
        assert "App One" in lines[2]
        assert "com.example.app2" in lines[3]
        assert "App Two" in lines[3]
        # Summary line
        assert "2 applications found" in lines[-1]

    def test_enumerate_failure_exits(self):
        mock_device = MagicMock()
        mock_device.enumerate_applications.side_effect = Exception("device error")
        with pytest.raises(SystemExit):
            list_applications(mock_device)


class TestSpawnR2fridaProcess:

    @patch("r2flutch.device.r2pipe")
    def test_spawn_success(self, mock_r2pipe):
        mock_r2f = MagicMock()
        mock_r2pipe.open.return_value = mock_r2f

        result = spawn_r2frida_process("com.example.app", "usb-123")
        mock_r2pipe.open.assert_called_once_with("frida://spawn/usb/usb-123/com.example.app")
        assert result is mock_r2f

    @patch("r2flutch.device.r2pipe")
    def test_spawn_failure_exits(self, mock_r2pipe):
        mock_r2pipe.open.side_effect = Exception("spawn failed")
        with pytest.raises(SystemExit):
            spawn_r2frida_process("com.example.app", "usb-123")


class TestKillProcess:

    def test_kill_success(self):
        mock_device = MagicMock()
        mock_r2f = MagicMock()
        mock_r2f.cmd.return_value = "1234"

        kill_process(mock_device, mock_r2f)
        mock_device.kill.assert_called_once_with(1234)

    @patch("r2flutch.device.print_console")
    def test_kill_failure_prints_warning(self, mock_print):
        mock_device = MagicMock()
        mock_device.kill.side_effect = Exception("kill error")
        mock_r2f = MagicMock()
        mock_r2f.cmd.return_value = "1234"

        # Should not raise
        kill_process(mock_device, mock_r2f)
        # Warning message should be printed
        warning_calls = [c for c in mock_print.call_args_list if "error" in str(c).lower() or "kill" in str(c).lower()]
        assert len(warning_calls) > 0
