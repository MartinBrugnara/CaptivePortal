# Captive Portal
===
Lightweight dockerized Captive Portal based on iptables.


## Implementation note:
* #### Identification:<br>
User identification is made binding IP&MAC with an UID (User ID).


* #### Authentication:<br>
The authentication module can be easly extended as needed.
Captive provide two function *Grant* and *Revoke* to manage the connectivity of the user.

All the rest is pure html and sql call, no dark magic I promise,
that can be modified without pain ;)

* #### Modes:<br>
    * Same thing as Authentication.
    * Currently implementation:
        * Activation for N hours/days
        * One device per account a time

### Requirements
* arp
* iptables
* golang
