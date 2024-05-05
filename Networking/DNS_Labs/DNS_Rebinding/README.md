# Answer in my observation
## Task 1
- The page can successfully set the thermostat's temperature is the page from the local DNS due to the same-origin policy. The policy denies the malicious websites to run JavaScript in a browser and read data from the response content of cross-originn requests through scripts.

## Task 2 + 3
- Before accessing to the domain `http://www.attacker32.com/change`, which is the Attacker's website. In the Attacker's nameserver container, the content of `/etc/bind/zone_attacker32.com` will be:
```
$TTL 3D
@       IN      SOA   ns.attacker32.com. admin.attacker32.com. (
                2008111001
                8H
                2H
                4W
                1D)

@       IN      NS    ns.attacker32.com.

@       IN      A     10.9.0.180
www     IN      A     10.9.0.180
ns      IN      A     10.9.0.153
*       IN      A     10.9.0.100
```

- Before clicking the button, we will map the `www.attacker32.com` to the IP address of IOT device which is `192.168.60.80`, the content of `zone_attacker32.com` will be:
```
$TTL 3D
@       IN      SOA   ns.attacker32.com. admin.attacker32.com. (
                2008111001
                8H
                2H
                4W
                1D)

@       IN      NS    ns.attacker32.com.

@       IN      A     10.9.0.180
www     IN      A     192.168.60.80
ns      IN      A     10.9.0.153
*       IN      A     10.9.0.100
```

- Here's the result of **Task 2** and **Task 3**:
* Task 2

![Screenshot 2024-05-05 180906](https://github.com/OceanTran999/SEEDLAB/assets/100577019/8bb9b7f3-7173-4e5e-ba91-cc0977ed7ddc)

![Screenshot 2024-05-05 181038](https://github.com/OceanTran999/SEEDLAB/assets/100577019/c53485d1-99db-4ac9-b0b8-68e44c73cd56)

* Task 3

![Screenshot 2024-05-05 181054](https://github.com/OceanTran999/SEEDLAB/assets/100577019/a2c9328d-5dfd-4226-bae5-f1840f80302a)

![Screenshot 2024-05-05 181109](https://github.com/OceanTran999/SEEDLAB/assets/100577019/d6e69675-172e-4d76-8118-15772228e914)

## References:
1. https://unit42.paloaltonetworks.com/dns-rebinding/
2. https://heimdalsecurity.com/blog/dns-rebinding/ 
