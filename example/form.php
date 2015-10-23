<?php

/**
 * Copyright 2015 François Kooman <fkooman@tuxed.net>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
require_once dirname(__DIR__).'/vendor/autoload.php';
require_once __DIR__.'/SimpleTpl.php';

use fkooman\Rest\Service;
use fkooman\Rest\Plugin\Authentication\Form\FormAuthentication;
use fkooman\Rest\Plugin\Authentication\Form\FormUserInfo;

// this is a very simple TemplateManagerInterface implementation just returning
// strings, in a real application you would use `fkooman/tpl-twig` for example
$tpl = new SimpleTpl();

// initialize the FormAuthentication class, provide it a function that 
// returns a hash for the provided userName, here it returns the hashed value
// of bar (using https://secure.php.net/password_hash)
$auth = new FormAuthentication(
    function ($userName) {
        return '$2y$10$L/pq7XXpV54.iAk2EE74deR4yR54yEaZb92.gxH2jDEAZkpcWbhiW'; // bar
    },
    $tpl, // the template engine
    array('realm' => 'Example') // the realm for a 401
);

$service = new Service();
$service->getPluginRegistry()->registerDefaultPlugin($auth);

// disable the plugin for the indexPage, we do not need to be logged in 
// there...
$service->get(
    '/',
    function () use ($tpl) {
        return $tpl->render(
            'indexPage',
            array()
        );
    },
    array(
        'fkooman\Rest\Plugin\Authentication\Form\FormAuthentication' => array(
            'enabled' => false,
        ),
    )
);

// here we do need to login to be able to watch this page, the authentication
// plugin takes care of the rest...
$service->get(
    '/welcomePage',
    function (FormUserInfo $u) use ($tpl) {
        return $tpl->render(
            'welcomePage',
            array(
                'user_id' => $u->getUserId(),
            )
        );
    }
);
$service->run()->send();
