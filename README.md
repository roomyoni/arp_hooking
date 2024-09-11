Utilizing major function swaps to hook the ioctl request used to query the ARP table.

Remarks:
- Designed to be loaded via a manual mapper like TheCruZ's "KDMAPPER"
- Simply makes the function return ACCESS_DENIED, but ideally you should parse the ioctl buffer and instead change every mac entry (assuming this will be used for spoofing)


Demonstration:
- Before Mapping
  ![image](https://github.com/user-attachments/assets/a492b9c8-8c85-4600-becd-be2a1fbd642b)

- After Mapping
  ![image](https://github.com/user-attachments/assets/6df64897-e018-4c6f-a6ab-a30654dc8cf5)

