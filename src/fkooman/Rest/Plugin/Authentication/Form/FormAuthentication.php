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
namespace fkooman\Rest\Plugin\Authentication\Form;

use fkooman\Http\SessionInterface;
use fkooman\Http\Session;
use fkooman\Http\Request;
use fkooman\Rest\Service;
use fkooman\Rest\Plugin\Authentication\AuthenticationPluginInterface;
use fkooman\Tpl\TemplateManagerInterface;
use fkooman\Http\Response;
use fkooman\Http\RedirectResponse;
use fkooman\Http\Exception\BadRequestException;

class FormAuthentication implements AuthenticationPluginInterface
{
    /** @var callable */
    private $retrieveHash;

    /** @var \fkooman\Tpl\TemplateManagerInterface */
    private $templateManager;

    /** @var \fkooman\Http\SessionInterface */
    private $session;

    public function __construct(callable $retrieveHash, TemplateManagerInterface $templateManager, SessionInterface $session = null)
    {
        $this->retrieveHash = $retrieveHash;
        $this->templateManager = $templateManager;
        if (is_null($session)) {
            $session = new Session('form');
        }
        $this->session = $session;
    }

    public function isAuthenticated(Request $request)
    {
        $authFormUserName = $this->session->get('_auth_form_user_name');
        if (is_null($authFormUserName)) {
            return false;
        }

        return new FormUserInfo($authFormUserName);
    }

    public function init(Service $service)
    {
        $service->post(
            '/_auth/form/verify',
            function (Request $request) {
                $httpReferrer = $request->getHeader('Referer');
                if (null === $httpReferrer) {
                    throw new BadRequestException('Referrer header not sent');
                }

                // delete possibly stale auth session
                $this->session->delete('_auth_form_user_name');
                $this->session->delete('_auth_form_invalid_credentials');
                $this->session->delete('_auth_form_invalid_user_name');

                // validate password
                $userName = $request->getPostParameter('userName');
                $userPass = $request->getPostParameter('userPass');

                $passHash = call_user_func($this->retrieveHash, $userName);
                if (false === $passHash || !password_verify($userPass, $passHash)) {
                    $this->session->set('_auth_form_invalid_credentials', true);
                    $this->session->set('_auth_form_invalid_user_name', $userName);
                } else {
                    $this->session->set('_auth_form_user_name', $userName);
                    $this->session->delete('_auth_form_invalid_credentials');
                    $this->session->delete('_auth_form_invalid_user_name');
                }

                return new RedirectResponse($httpReferrer, 302);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array('enabled' => false),
            )
        );

        $service->post(
            '/_auth/form/logout',
            function (Request $request) {
                $this->session->destroy();

                $rootUrl = $request->getUrl()->getRootUrl();
                $redirectToParameter = $request->getPostParameter('redirect_to');
                $redirectTo = self::validateRedirectTo($rootUrl, $redirectToParameter);

                return new RedirectResponse($redirectTo, 302);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array('enabled' => false),
            )
        );
    }

    public function requestAuthentication(Request $request)
    {
        $response = new Response(200);
        $response->setHeader('X-Frame-Options', 'DENY');
        $response->setHeader('Content-Security-Policy', "default-src 'self'");
        $response->setBody(
            $this->templateManager->render(
                'formAuth',
                array(
                    'login_hint' => $request->getUrl()->getQueryParameter('login_hint'),
                    '_auth_form_invalid_credentials' => $this->session->get('_auth_form_invalid_credentials'),
                    '_auth_form_invalid_user_name' => $this->session->get('_auth_form_invalid_user_name'),
                )
            )
        );

        return $response;
    }

    private static function validateRedirectTo($rootUrl, $redirectToParameter)
    {
        if (is_null($redirectToParameter)) {
            return $rootUrl;
        }

        // MUST be valid absolute URL
        if (false === filter_var($redirectToParameter, FILTER_VALIDATE_URL)) {
            throw new BadRequestException('invalid redirect_to URL');
        }

        return $redirectToParameter;
    }
}
