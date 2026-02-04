def patch_call_ori(file,where,end,arch = "amd64"):
	print(hex(end))

	length = p32((end - (where + 5 )) & 0xffffffff)
	order = '\xe8'+length
	print(disasm(order,arch=arch))
	file.patch_address(where,[ord(i) for i in order])
	
def patch_call(target,begin,arch = "amd64"):
	#print hex(end)

	order = ((target - (begin + 5 )) & 0xffffffff)
	#order = '\xe8'+length
	order_s = hex(order)[2:].upper().strip("L").rjust(8,"0")
	res = ""
	for i in range(8,0,-2):
		res += " " + order_s[i-2:i] 
	print("E8" + res)
	print(hex(order))

patch_call(0x0000000000000B00,0x0000000000000998)
patch_call(0x0000000000000780,0x0000000000000B0A)
#patch_call(0x420DC0,0x407830)
#patch_call(0x420D90,0x000000000040783F)
#0x4018de
#0x401f8c
#0x401f74

# E8 33 DD FF FF
# 48 C7 05 3F 0E 20 00 00 00 00 00
#q7WaTQrfuSt3dtquWVNR7b3hnEkntXQbkfwy4UtbwzakuaCsTFkzrrJQEsAN
#12 6 13 9 8 10 1 20 11 16 17 19 15
#print chr(0x6c)
#080483F0