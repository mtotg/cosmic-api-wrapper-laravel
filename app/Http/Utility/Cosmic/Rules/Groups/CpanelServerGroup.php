<?php

namespace App\Http\Utility\Cosmic\Rules\Groups;

use App\Http\Utility\Cosmic\Rules\Tcp;
use App\Http\Utility\Cosmic\Rules\Udp;
use App\Http\Utility\Cosmic\Wrapper;

class CpanelServerGroup
{
    public function __construct()
    {
        return $this->rules();
    }

    private function rules()
    {
        $http = new Tcp(80, Wrapper::$RULE_PASS);
        $https = new Tcp(443, Wrapper::$RULE_PASS);
        $cpanel_2083 = new Tcp(2083, Wrapper::$RULE_PASS);
        $cpanel_2084 = new Tcp(2084, Wrapper::$RULE_PASS);
        $cpanel_2086 = new Tcp(2086, Wrapper::$RULE_PASS);
        $cpanel_2087 = new Tcp(2087, Wrapper::$RULE_PASS);
        $ssh = new Tcp(22, Wrapper::$RULE_PASS);
        $smtp = new Tcp(25, Wrapper::$RULE_PASS);
        $drop_all_tcp = new Tcp(0, Wrapper::$RULE_DROP);
        $drop_all_udp = new Udp(0, Wrapper::$RULE_DROP);

        return array(
            $http,
            $https,
            $ssh,
            $cpanel_2083,
            $cpanel_2084,
            $cpanel_2086,
            $cpanel_2087,
            $smtp,
            $drop_all_udp,
            $drop_all_tcp
        );
    }
}
