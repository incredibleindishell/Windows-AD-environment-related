# How to use responder tool to perform exploitation in windows environment by stealing NTLMv2 hashes.

Download link for responder is: - <a href="https://github.com/lgandx/Responder">https://github.com/lgandx/Responder</a>

This tool is capable of poisoning LLMNR and NBT-NS requests.

Let's assume, we are connected to Windows Active directory environment and when any of the machine is network will try to resolve the destination machine using LLMNR or NBT-NS requests, Responder will pretend as the destination machine. When Victim machine will try to login to attacker machine, responder will capture the NTLMv2 hashes of the victim machine user.

In demo, 2 attacks has been discussed.
1. Just capturing the NTLMv2 hashes and cracking them using "Hashcat" password cracking tool.
2. Using Responder and Multirelay.py script which will perform NTLMv2 hashes relay to a machine which is having "SMB signing disabled". If relay happen successfully, will have shell access on the target machine.

# Capturing the NTLMv2 Hashes
Run the Responder by specifiying the ethernet interface of the machine with argument -I , in my case it was eth0 
<br>Command is 

 	python Responder.py -I <Interface_card_name> 
For example

 	python Responder.py -I eth0

<img src="https://raw.githubusercontent.com/incredibleindishell/Windows-AD-environment-related/master/Responder/images/1.png">
Responder listening mode will be like this <br>
<img src="https://raw.githubusercontent.com/incredibleindishell/Windows-AD-environment-related/master/Responder/images/2.png">

If any user in network trying to access share which for machine is not having IP or user type share name incorrectly, that machine will trigger LLMNR request to network and responder will answer to that request by saying that i am that machine, please provide me NTLMv2 hash and access the resource.

<img src="https://raw.githubusercontent.com/incredibleindishell/Windows-AD-environment-related/master/Responder/images/3.png">

Here, user "box1" (machine IP 192.168.56.101) is trying to access a share having name "pwned68". When machine triggered LLMNR request, Responder responded to that request and captured the NTLMv2 hashes of the user "box1" from domain "DC2".

Now, we need to crack this hash to get the plain text password. 
"Hashcat" is awesome tool to perform fastest hashcracking. It support CPU/GPU hash cracking and has support for multiple hash formats.
Hahcat official download website is: - <a href="https://hashcat.net/hashcat/">https://hashcat.net/hashcat/</a>
Download good password dictionary, here is one <a href="https://hashkiller.co.uk/downloads.aspx">https://hashkiller.co.uk/downloads.aspx</a>
Run the hashcat and wait if luck is on our side.

<img src="https://raw.githubusercontent.com/incredibleindishell/Windows-AD-environment-related/master/Responder/images/4.png">

After getting the plain text password, we can use this password to login to other machines on windows Domain to see if any senstive information we can access on other machine.

# Getting Shell access on a machine in network
Responder has few other tools as well which allows attacker to perform attacks like gaining shell access to a machine in network by relaying NTLMv2 hases. Here, condition is, captured hash will help us to get shell access if the user for which we captured hashes, has 'administrator' access on the target machine. Normal Domain user hash wont help us to get shell access on machine.
In my case, one of the admin user tried to access a non-existing share, Responder poisoned it and later Multirelay.py script used captured NTLMv2 hash to login to a machine which is the part of Windows domain network.

To setup this, make a change in 'Responder.conf' file. Open the Responder.conf file and set the value of SMB and HTTP to 'Off', so that responder does not capture the hash but Multirelay.py do the task.

<img src="https://raw.githubusercontent.com/incredibleindishell/Windows-AD-environment-related/master/Responder/images/7.1.png">

Now, run the RunFinger.py script to identify the HOST machines in the network which has 'SMB signing' set to 'False', because we can perform attack to only those machine which is not having 'SMB signing' set to 'True'. 
This script is available in 'tools' directory of responder, enter into that directory first. RunFinger.py script expect IP range for which it will check whether live HOSTS are having SMB signing enabled or not.
Command to run the RunFinger.py script is: -

    python  RunFinger.py -i IP_Range
 Example: -
 
    python RunFinger.py -i 192.168.56.100-200
<img src="https://raw.githubusercontent.com/incredibleindishell/Windows-AD-environment-related/master/Responder/images/5.png">

Output of the script will be like this

<img src="https://raw.githubusercontent.com/incredibleindishell/Windows-AD-environment-related/master/Responder/images/6.png">

For me, only 2 machines are live. One is Domain controller machine and second one is 'Windows 7' which is part of Windows domain. 
Machine having IP 192.168.56.101 does not has SMB signing enabled. So, we can try to perform NTLMv2 hash relay against this machine.
After discovering the machines, let's setup responder and multirelay.py script to get the access on machine which is not having 'SMB signing' enabled.
Run below mentioned commands to start Responder and Multirelay.py script in 2 different terminals 

In first terminal, run responder

    python Responder.py -I <interface_card>
In second terminal, run Multirelay.py

    python MultiRelay.py -t <target_machine_IP> -u ALL
<img src="https://raw.githubusercontent.com/incredibleindishell/Windows-AD-environment-related/master/Responder/images/7.png">    
 
Both the scripts in action will be like this 

<img src="https://raw.githubusercontent.com/incredibleindishell/Windows-AD-environment-related/master/Responder/images/8.png">
Now, the moment, any admin user in Domain try to access/mis-spelled share which does not exist, responder will poison the response. Multirelay.py will do rest of the stuff by capturing the NTLMv2 hahses and will relat them to target machine. Successful relay will get us shell access on the target machine (windows 7 in my case)

<img src="https://raw.githubusercontent.com/incredibleindishell/Windows-AD-environment-related/master/Responder/images/9.png">

Once we get the shell access, we can perform other stuffs as well and one of them is loading 'Mimikatz' which can perform tasks like dumping plain text password/hashes of currently logged in users or grabbing hashes of local users from SAM file.

<img src="https://raw.githubusercontent.com/incredibleindishell/Windows-AD-environment-related/master/Responder/images/10.png">

--==[[Greetz to]]==--

zero cool, code breaker ica, root_devil, google_warrior, INX_r0ot,Darkwolf indishell, Baba, Silent poison India, Magnum sniper, ethicalnoob Indishell, Local root indishell, Irfninja indishell, Reborn India, L0rd Crus4d3r, cool toad, Hackuin, Alicks, Gujjar PCP, Bikash, Dinelson Amine, Th3 D3str0yer, SKSking, rad paul, Godzila, mike waals, zoo zoo, cyber warrior, shafoon, Rehan manzoor, cyber gladiator, 7he Cre4t0r, Cyber Ace, Golden boy INDIA, Ketan Singh, Yash, Aneesh Dogra, AR AR, saad abbasi, hero, Minhal Mehdi, Raj bhai ji, Hacking queen, lovetherisk, D2 and rest of TEAM INDISHELL

--==[[Love to]]==--

My Father,Ritu Tomer Rathi,cold fire hacker, Mannu, ViKi, Ashu bhai ji, Soldier Of God, Bhuppi, Gujjar PCP, rafay baloch
Mohit, Ffe, Ashish, Shardhanand, Budhaoo, Jagriti, Salty, Hacker fantastic, Jennifer Arcuri, Don(Deepika kaushik) and all lovely people around the world <3
