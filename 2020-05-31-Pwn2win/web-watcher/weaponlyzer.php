<?php

    function weaponlyzer($home_url, $about_url, $contact_url) {
        
        $targets = [$home_url, $about_url, $contact_url];
        $applications = [];
        $i = 0;

        for($i = 0; $i < 3; $i++) {
            $output = shell_exec('timeout -k 3s 20s wappalyzer -w 8 ' . escapeshellarg(escapeshellcmd($targets[$i])));
            $json = json_decode($output, true);

            if (json_last_error() === JSON_ERROR_NONE) {
            
                unlink(realpath(substr(parse_url($targets[$i])["path"], 1)));

                foreach ($json['applications'] as $tech) {

                    $entry = new class{};

                    $entry->name = $tech["name"];
                    $entry->version = $tech["version"];

                    $category = array_values($tech["categories"])[0];

                    if (!array_key_exists($category, $applications))
                        $applications[$category] = [];
                    
                        if(!in_array($entry, $applications[$category], false))
                            array_push($applications[$category], $entry);

                } 
            } elseif ($output == '') {
                return 'Couldn\'t analyze your file, please ask the admin to try weaponlyze in your page - URL: ' . substr(parse_url($targets[$i])["path"], 1);
            } else {
                unlink(realpath(substr(parse_url($targets[0])["path"], 1)));
                unlink(realpath(substr(parse_url($targets[1])["path"], 1)));
                unlink(realpath(substr(parse_url($targets[2])["path"], 1)));
            }
        
        }

        $json = json_encode($applications);
        return $json; 
    }

