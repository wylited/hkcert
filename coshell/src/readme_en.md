# Notice to Player

What is this? Copy it

## Question attachment

Challenge path: /challenge/chal

Note: Please backup the competition question attachment to your local before repairing, otherwise the original attachment will be overwritten after repairing!

### Player Environment

Player can only upload the repair file to the patch directory via sftp. The key directory functions are as follows:
```bash
challenge #question attachment, the competition question file in this directory will be replaced after being fixed
flag      #flag file
patch     #patch directory
```

### Repair steps

1. Use scp to upload the repair file to the specified path
```shell
scp -i /path/to/your_private_key.pem -s -P 22 /path/to/your_patched_file ctf@<server_ip>:/patch/patched
```

2. Create a new version confirmation file
```shell
scp -i /path/to/your_private_key.pem -s -P 22 /path/to/your_version_file ctf@<server_ip>:/patch/version
```
Patching will occur when both of the following files exist in the patch directory:

```bash
patched # file after repair
version # confirm the repair of the signature file
```

Upload the fix file to the /patch directory, rename it as patched, and then create a version file to confirm whether to apply the patch. Wait for about 30 seconds, and the environment will automatically replace the file and clear the patch directory. The replaced file can be viewed under /challenge

### Repair Instructions

1. Repair should be targeted at the code segments near the vulnerability points. Functions unrelated to the vulnerability points are not allowed to be modified, while maintaining the normal operation of the competition service and the interaction logic unchanged
2. The size of the competition question file must remain unchanged, and modifications are allowed up to a maximum of 30 bytes

