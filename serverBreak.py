import os
import time

def main():
	output = ''
	cmd = ''
	for i in range(0, 10000):
		output += 'a'
		cmd = 'echo ' + output + ' | netcat 0.0.0.0 9879'
		#print(cmd)
		os.system(cmd)
		print('\n')

if __name__ == "__main__":
	main()