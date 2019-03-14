<?php
/**
 * IPGroup Plugin
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Sascha Bendix <sascha.bendix@localroot.de>
 * @author     Marcel Pennewiss <opensource@pennewiss.de>
 * @author     Peter Grosse <pegro@fem-net.de>
 */

if(!defined('DOKU_INC')) die();
if(!defined('DOKU_PLUGIN')) define('DOKU_PLUGIN',DOKU_INC.'lib/plugins/');

require_once(DOKU_PLUGIN.'action.php');

class action_plugin_ipgroup extends DokuWiki_Action_Plugin {

    /**
     * Return some info
     */
    function getInfo() {
        return array(
            'author' => 'Sascha Bendix, Marcel Pennewiß, Peter Große',
            'email'  => 'webserver@fem.tu-ilmenau.de',
            'date'   => '2011-11-14',
            'name'   => 'IPGroup Action Plugin',
            'desc'   => 'Allows administrators to map (anonymous) users from specified networks to a single group.'
        );
    }

    /**
     * Register event handlers
     */
    function register(&$controller) {
        $controller->register_hook('DOKUWIKI_STARTED', 'BEFORE', $this, 'start');
        $controller->register_hook('FEED_OPTS_POSTPROCESS', 'BEFORE', $this, 'start');
        $controller->register_hook('SEARCH_QUERY_PAGELOOKUP', 'BEFORE', $this, 'start');
        $controller->register_hook('MEDIAMANAGER_STARTED', 'BEFORE', $this, 'start');
    }

    function start(&$event, $param) {

	// get remote ip when user is using a proxy
	$ip = clientIP(true);

	// read config file or create
	$filecontent = @file(DOKU_CONF.'ipgroup.conf', FILE_SKIP_EMPTY_LINES);
	if ($filecontent === false) { $filecontent = array(); }

	// check current ip against each network-definition
	foreach ($filecontent as $line) {
		// seperate network and group and trim spaces
		list($network,$group) = explode(';', $line);
		$network = rtrim($network);
		$group = rtrim($group);

		// seperate cidr-suffix from network
		$network_bits = substr($network,strpos($network,'/')+1);

		// only go further if the acces is done via the same ip version then the network we are currently looking at
		if (filter_var($network_address,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4) == filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)
			|| (filter_var($network_address,FILTER_VALIDATE_IP,FILTER_FLAG_IPV6) == filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV6))) {
			
			// check if ip matches network
			if ($this->ip2pton($ip."/".$network_bits) === $this->ip2pton($network)) {
			    // add group to list
			    $groups[] = $group;
			}
		}
	}

	if (count($groups) > 0) {
		// $INFO['perm'] in written in lib/common.php/pageinfo():137 (called by doku.php:51)
		// this plugin is executed later in lib/actions.php/act_dispatch($ACT):33 (called by doku.php:84)
		// at the first time, auth_aclcheck() is called with an empty groups array
		// so we call it again here with our ip trustee group
		// the $INFO['perm'] variable is first used in lib/actions.php/act_checkperms($ACT):255 (called by lib/actions.php/act_dispatch($ACT):143)
		// so this setting is right in between the both occurrences

		// merge existing group-informations and new groups
		$grps = array_merge((array)$GLOBALS['USERINFO']['grps'],$groups);
		// remove duplicate entries
		$grps = array_values(array_unique($grps));

		// Overwrite Permissions
	        $GLOBALS['USERINFO']['grps'] = $grps;
		$GLOBALS['INFO']['perm'] = auth_aclcheck($GLOBALS['ID'],'', $grps);

		// Overwrite writable/editable-flags (as done in lib/common.php/pageinfo():137 before)
		if($GLOBALS['INFO']['exists']){
		    $GLOBALS['INFO']['writable'] = (is_writable($GLOBALS['INFO']['filepath']) &&
 				                        ($GLOBALS['INFO']['perm'] >= AUTH_EDIT));
 		 }else{
		    $GLOBALS['INFO']['writable'] = ($GLOBALS['INFO']['perm'] >= AUTH_CREATE);
		}

		$GLOBALS['INFO']['editable']  = ($GLOBALS['INFO']['writable'] && empty($GLOBALS['INFO']['lock']));

	}
    }
    
    /**
     * calc ip-adress to in_addr-representation
     * @link http://www.php.net/manual/de/function.inet-pton.php#93501 source and idea 
     */
    function ip2pton($ipaddr) {

        // Strip out the netmask, if there is one.
        $cx = strpos($ipaddr, '/');
        if ($cx)
        {
            $subnet = (int)(substr($ipaddr, $cx+1));
            $ipaddr = substr($ipaddr, 0, $cx);
        }
        else $subnet = null; // No netmask present

        // Convert address to packed format
        $addr = inet_pton($ipaddr);

        // Convert the netmask
        if (is_integer($subnet))
        {
            // Maximum netmask length = same as packed address
            $len = 8*strlen($addr);
            if ($subnet > $len) $subnet = $len;
 
            // Create a hex expression of the subnet mask
            $mask  = str_repeat('f', $subnet>>2);
            switch($subnet & 3)
            {
                case 3: $mask .= 'e'; break;
                case 2: $mask .= 'c'; break;
                case 1: $mask .= '8'; break;
            }
            $mask = str_pad($mask, $len>>2, '0');

            // Packed representation of netmask
            $mask = pack('H*', $mask);
        }

        // Return logical and of addr and mask
	    return ($addr & $mask);
    }
}
