# Captive Portal
===
Lightweight <del>dockerized (maybe in the future)</del> Captive Portal based on GO and iptables.

##### Event if it seams to work ... it's far from to be production ready #####


## Implementation note:
* #### Identification:<br>
User identification is made binding IP&MAC with an UID (User ID).


* #### Authentication:<br>
The authentication module can be easly extended as needed.
Captive provide two function *Grant* and *Revoke* to manage the connectivity of the user.<br>
All the rest is pure html and sql call, no dark magic I promise,
that can be modified without pain ;)


* ####  Modes:<br>
    * Same thing as Authentication.
    * Currently implementation:
        * Activation for N hours/days
        * One device per account a time

### Requirements
* arp
* iptables
* golang

### ACK
Based on the idea of:
http://www.andybev.com/index.php/Using_iptables_and_PHP_to_create_a_captive_portal
