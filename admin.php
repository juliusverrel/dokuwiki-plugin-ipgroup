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

require_once(DOKU_PLUGIN.'admin.php');

class admin_plugin_ipgroup extends DokuWiki_Admin_Plugin {

    /**
     * Return some info
     */
    function getInfo() {
        return array(
            'author' => 'Sascha Bendix, Marcel Pennewiß, Peter Große',
            'email'  => 'webserver@fem.tu-ilmenau.de',
            'date'   => '2011-11-14',
            'name'   => 'IPGroup Plugin',
            'desc'   => 'Allows administrators to map (anonymous) users from specified networks to a single group.'
        );
    }

    /**
     * This functionality should be available only to administrator
     */
    function forAdminOnly() {
        return true;
    }

    /**
     * Handles user request
     */
    function handle() {
        if (isset($_REQUEST['network']) && ($_REQUEST['network'] != '')
	    && isset($_REQUEST['group']) && ($_REQUEST['group'] != '')) {
            // network and group should be added to the list of trusted networks
            // check input
	    $config_row = $_REQUEST['network'].';'.$_REQUEST['group']."\n";
            $slash_pos = strpos($_REQUEST['network'],'/');
            if (($slash_pos) && (filter_var(substr($_REQUEST['network'],0,$slash_pos),FILTER_VALIDATE_IP))) {
                $filecontent = @file(DOKU_CONF.'ipgroup.conf', FILE_SKIP_EMPTY_LINES);
                if ($filecontent && (sizeof($filecontent) > 0)) {
                    if (in_array($config_row, $filecontent)) {
                        msg($this->getLang('already'), -1);
                        return;
                    }
                }
                io_saveFile(DOKU_CONF.'ipgroup.conf', $config_row, true);
            } else {
                msg($this->getLang('invalid_ip'), -1);
            }
        } elseif (isset($_REQUEST['delete']) && is_array($_REQUEST['delete']) && (sizeof($_REQUEST['delete']) > 0)) {
            // delete network/group-mapping from the list
	    if (!io_deleteFromFile(DOKU_CONF.'ipgroup.conf', key($_REQUEST['delete'])."\n")) {
	    	msg($this->getLang('failed'), -1);
	    }
        } elseif (isset($_REQUEST['clear'])) {
            if (file_exists($conf['cachedir'].'/ipgroup')) {
                @unlink($conf['cachedir'].'/ipgroup');
            }
        }
    }

    /**
     * Shows edit form
     */
    function html() {
        global $conf;

        print $this->locale_xhtml('intro');

        print $this->locale_xhtml('list');
        ptln("<div class=\"level2\">");
        ptln("<form action=\"\" method=\"post\">");
        formSecurityToken();
        $networks = @file(DOKU_CONF.'ipgroup.conf', FILE_SKIP_EMPTY_LINES);
        if ($networks && (sizeof($networks) > 0)) {
            ptln("<table class=\"inline\">");
            ptln("<colgroup width=\"250\"></colgroup>");
            ptln("<colgroup width=\"150\"></colgroup>");
            ptln("<thead>");
            ptln("<tr>");
            ptln("<th>".$this->getLang('network')."</th>");
            ptln("<th>".$this->getLang('group')."</th>");
            ptln("<th>".$this->getLang('delete')."</th>");
            ptln("</tr>");
            ptln("</thead>");
            ptln("<tbody>");
            foreach ($networks as $network) {
                $network = rtrim($network);
		list($network, $group) = explode(';', $network);
                ptln("<tr>");
                ptln("<td>".rtrim($network)."</td>");
                ptln("<td>".rtrim($group)."</td>");
                ptln("<td>");
                ptln("<input type=\"submit\" name=\"delete[".$network.";".$group."]\" value=\"".$this->getLang('delete')."\" class=\"button\">");
                ptln("</td>");
                ptln("</tr>");
            }
            ptln("</tbody>");
            ptln("</table>");
        } else {
            ptln("<div class=\"fn\">".$this->getLang('noips')."</div>");
        }
        ptln("</form>");
        ptln("</div>");

        print $this->locale_xhtml('add');
        ptln("<div class=\"level2\">");
        ptln("<form action=\"\" method=\"post\">");
        formSecurityToken();
        ptln("<label for=\"ip__add\">".$this->getLang('network').":</label>");
        ptln("<input id=\"ip__add\" name=\"network\" type=\"text\" maxlength=\"44\" class=\"edit\">");
        ptln("<label for=\"group__add\">".$this->getLang('group').":</label>");
        ptln("<input id=\"group__add\" name=\"group\" type=\"text\" maxlength=\"64\" class=\"edit\">");
        ptln("<input type=\"submit\" value=\"".$this->getLang('add')."\" class=\"button\">");
        ptln("</form>");
        ptln("</div>");

        if (file_exists($conf['cachedir'].'/ipgroup')) {
            @unlink($conf['cachedir'].'/ipgroup');
        }
    }
}
