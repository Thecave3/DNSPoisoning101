run_listener:
	xterm -e 'python listener.py' 

run_bait:
	xterm -e 'python bait.py'

run_venom:
	xterm -e 'python venom.py'

all:
	run_listener 
	run_bait 
	run_venom