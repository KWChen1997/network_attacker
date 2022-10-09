# Cloud-Based Identification System for IoT Devices

The identification system takes advantage of the inherent resource constraints of IoT devices to distinguish them from general-purpose computing devices, and to distinguish between different types of IoT devices.

The identification system is divided into two parts, the modules executed on a Wi-Fi AP and the modules on a cloud server.

## Prerequisites

- hostapd + udhcpd
    - [Scripts to Create a Wi-Fi Hotspot with hostapd and udhcpd on Linux - Wireless Router Access Point](https://www.youtube.com/watch?v=zcAIZ1YFKMo)
        - To set up *hostapd* and *udhcpd* services.
    - [Linux下使用hostapd建立Wi-Fi訪問熱點](https://b8807053.pixnet.net/blog/post/349831267-linux%e4%b8%8b%e4%bd%bf%e7%94%a8hostapd-%e5%bb%ba%e7%ab%8b-wifi%e8%a8%aa%e5%95%8f%e7%86%b1%e9%bb%9e)
        - To enable Wi-Fi Protected Access (WPA).

- Scapy

```
sudo apt install python3-scapy
```

- scikit-learn

```
pip3 install -U scikit-learn
```

- Joblib

```
pip3 install joblib
```

## Usage

### Turn laptop into Wi-Fi AP.

Enable *hostapd* and *udhcpd* services to make the laptop act as a Wi-Fi AP and a DHCP server at the same time.

```
./wifi_ap on
```

Disable *hostapd* and *udhcpd* services.

```
./wifi_ap off
```

Display current statuses of the Wi-Fi interface, *iptables*, *hostapd* and *udhcpd* services.

```
./wifi_ap
```

### Automatic set-up trace collection

1. Collect a set-up network trace of a specific device upon its appearance in the Wi-Fi network.
2. Disconnect the device from the Wi-Fi network when the set-up is finished.
3. Block the device from reconnecting to the Wi-Fi network for a specific time.
4. Allow the device to reconnect to the Wi-Fi network.
    - IoT devices are supposed to automatically reconnect to the network.
5. Repeat steps 1~4 to collect multiple set-up traces of the device.

```
sudo ./pcap.py
```

### Semiautomatic set-up trace collection

1. Collect a set-up network trace of a specific device upon its appearance in the Wi-Fi network.
2. Stop recording captured packets into the output pcap file when the set-up is finished.
    - The device remains online.
3. Wait for the operator to manually replug in the power supply of the device.
4. Repeat steps 1~3 to collect multiple set-up traces of the device.

```
sudo ./pcap_replug.py
```

### Train and test classifier.

1. Extract the resource-related features from specified training and testing datasets of pcap files.
    - Store the extracted features into CSV files.
2. Train a decision tree model using the extracted training samples.
    - Plot the trained decision tree, and store the model into a *Joblib* file.
3. Test the trained model using the extracted testing samples.

```
./main.py
```

### Start cloud-based identification system.

Start the modules on a Wi-Fi AP.

- **Trace collector**: collect the network traffic passing though the Wi-Fi AP.
- **Device detector**: detect new devices connecting to the Wi-Fi network, and initiate a device recognizer on the cloud server for each of them to identify its identity.
- **Verifier**: ask for user verification of the predicted identity of a device.

```
sudo ./dev_detr.py
```

Start the modules on the cloud server.

- **Device recognizer**: analyze the network traffic of a device to predict its identity.
- **Classification proxy**: maintain the **multi-layer classification tree**, and coordinate the requests to access the classification tree from different device recognizers.

```
sudo ./cld.py
```
