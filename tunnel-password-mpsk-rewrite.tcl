when RULE_INIT { 
    # Put this value to anything different than 0 to enable debug logging
    set static::debug 1
    # The RADIUS PSK need to be known to rewrite the Message-Authenticator field after modification of the reply content 
    set static::seckey "MyRADIUSsharedSecretKey"
    # The name of the SSID for which to replicate the Tunnel-Password value to the Aruba-mPSK-Passphrase VSA
    # (This value will be seen on the RADIUS requests, put into the Aruba-Essid-Name VSA)
    set static::aruba_ssid "test-mpsk" 
} 

when CLIENT_DATA { 
    # Check if the static::aruba_ssid is found on the Aruba-Essid-Name VSA (also permits to validate that this is a RADIUS request from an Aruba access-point) 
    if { [RADIUS::avp 26 "string" vendor-id 14823 vendor-type 5] eq $static::aruba_ssid } {
        # Extract the Code, ID, Request-Authenticator and Attributes values from the request
        # The Request-Authenticator value is very important as it needs to be used on the reply's Message-Authenticator and Response-Authenticator hashes
        binary scan [UDP::payload] H2H2x2H32H* req_rad_code req_rad_pid req_rad_auth req_rad_attrs 
        # Storing the key/value pair pid/authenticator on the session table, to be able to find the correct Request-Authenticator value when 
        # forging the reply (if the Access-Point sends a lot of requests in a short amount of time, multiple requests can be received, while waiting for the reply for the RADIUS)
        session add uie $req_rad_pid $req_rad_auth
        if {$static::debug} {
            log local0.info "Request RAD_CODE : $req_rad_code"
            log local0.info "Request RAD_PID : $req_rad_pid"
            log local0.info "Request RAD_AUTH : $req_rad_auth"
            binary scan [RADIUS::avp 80] H* mess_auth
            log local0.info "Request MESS_AUTH : $mess_auth"
        }
    }
} 

when SERVER_DATA {
    # If the reply messages contains a Tunnel-Password field
    if {[RADIUS::avp 69] ne ""} {
        # Extract the Packet Identifier of the reply to use it to find the matching Request-Authenticator
        binary scan [UDP::payload] H2H2 reply_rad_code reply_rad_pid
        set lookup_rad_auth [session lookup uie $reply_rad_pid]
        
        # If we have a stored Radius Authenticator value for the Packet identifier (request)
        if { $lookup_rad_auth ne "" } {
            if {$static::debug} {
                log local0.info "Rewriting access-accept. Cached RADIUS Request authenticator value is $lookup_rad_auth"
            }
            # Extract the Tunnel-Password field (tag and value)
            binary scan [RADIUS::avp 69] cH* tunn_tag tunn_value
            if {$static::debug} {
                log local0.info "Tunnel-password tag $tunn_tag"
                log local0.info "Tunnel-Password value $tunn_value"
            }
            # Remove all VSA from the reply 
            while {[RADIUS::avp 26] ne ""} {
                if {$static::debug} {
                    log local0.info "Removing VSA [RADIUS::avp 26]"
                }
                RADIUS::avp delete 26
            }
            # Remove the Tunnel-Password field 
            RADIUS::avp delete 69
            
            # Add the Aruba-mPSK-Passphrase VSA, with the value of the Tunnel-Password field 
            set vendor_id 14823
            set vendor_type 44
            set tunn_length [expr { [string length $tunn_value] / 2 + 2 }]
            log local0.info "Tunnel length $tunn_length"
            set attr [binary format IccH* $vendor_id $vendor_type $tunn_length $tunn_value] 
            RADIUS::avp insert 26 $attr octet
            
            # Get the modified RADIUS attributes 
            binary scan [UDP::payload] x20H* rad_attrs
            
            # Generate the Message-Authenticator value for the modified payload 
            # HMAC-MD5(Type+Identifier+Length+Request Authenticator+Attributes) where + denotes concatenation, and key is the RADIUS shared secret 
            binary scan [CRYPTO::sign -alg hmac-md5 -key $static::seckey [binary format H*H*SH*H* $reply_rad_code $reply_rad_pid [ UDP::payload length ] $lookup_rad_auth $rad_attrs ]] H* mess_auth
            if {$static::debug} {
                log local0.info "Reply Message-Authenticator (computed) is $mess_auth"
            }
            # Apply the modified value to the reply 
            RADIUS::avp replace 80 $mess_auth octet
            
            # Generate the RADIUS authenticator value for the modified payload 
            # MD5(Code+ID+Length+RequestAuth+Attributes+Secret) where + denotes concatenation
            # Need to scan again the payload which has been modified 
            binary scan [UDP::payload] x20H* rad_attrs 
            set b "[binary format H*H*SH*H*a* $reply_rad_code $reply_rad_pid [UDP::payload length] $lookup_rad_auth $rad_attrs $static::seckey]" 
            # Apply the modified value to the reply 
            UDP::payload replace 4 16 [md5 $b]   
        } else {
            log local0.info "Unable to find cached Request-Authenticator field for Radius Packet Identifier $reply_rad_pid"
        }
    }
}
