# Crapplet DDoS Shield - remove what shield-readonly.rsc added.
#
# The api-ssl service is disabled again only if nothing else needs it: check before running.
# traffic-flow itself is left enabled if other targets remain.
# Run:   /import file-name=shield-remove.rsc verbose=yes
{
:local shieldAddress "10.255.0.10"
:local shieldUser "shield-ro"

/ip traffic-flow target remove [find dst-address=$shieldAddress]
:if ([:len [/ip traffic-flow target find]] = 0) do={ /ip traffic-flow set enabled=no }
/user remove [find name=$shieldUser]
/user group remove [find name="shield-read"]
# Uncomment if api-ssl was enabled only for Shield:
# /ip service set api-ssl disabled=yes address=""
# /certificate remove [find name="shield-api"]
:put "Shield access and flow export removed."
}
