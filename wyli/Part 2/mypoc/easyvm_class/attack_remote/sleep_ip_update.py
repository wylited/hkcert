import os
import time
import subprocess

def TIMEOUT_COMMAND(command, timeout):
    """call shell-command and either return its output or kill it
    if it doesn't normally exit within timeout seconds and return None"""
    import subprocess, datetime, os, time, signal
    cmd = command.split(" ")
    start = datetime.datetime.now()
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    while process.poll() is None:
        time.sleep(0.2)
        now = datetime.datetime.now()
        if (now - start).seconds> timeout:
            os.kill(process.pid, signal.SIGKILL)
            os.waitpid(-1, os.WNOHANG)
            return None
    return "".join(process.stdout.readlines())

while True:
	for i in range(11,13 + 1):
		ip = "172.22.61.{ip}".format(ip = str(i))
		port = 9999
		try:
			print(TIMEOUT_COMMAND("python3 ./easyvm_overflow.py {ip} {port}".format(ip = ip,port = port),15))
			# os.system("python ./exp.py {ip} {port}".format(ip = ip,port = port))
		except KeyboardInterrupt:
			break
		except:
			pass
	time.sleep(10)
