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
use fkooman\Tpl\TemplateManagerInterface;

class SimpleTpl implements TemplateManagerInterface
{
    public function setDefault(array $templateVariables)
    {
    }

    public function render($templateName, array $templateVariables)
    {
        if ('indexPage' === $templateName) {
            return '<!DOCTYPE html>
                <html lang="en">
                    <head>
                        <meta charset="utf-8">
                        <title>Index</title>
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    </head>
                    <body>
                            <h2>Index</h2>
                            <p>Visit the <a href="welcomePage">Welcome Page</a>, you need to be logged in.</p>
                    </body>
                </html>';
        };

        if ('formAuth' === $templateName) {
            return sprintf('<!DOCTYPE html>
                <html lang="en">
                    <head>
                        <meta charset="utf-8">
                        <title>Sign In</title>
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    </head>
                    <body>
                            <h2>Sign In</h2>
                            <p>Please sign in with your username and password.</p>
                            <form method="post" action="_auth/form/verify">
                                <input type="text" name="userName" placeholder="Username" value="%s" autofocus required>
                                <input type="password" name="userPass" placeholder="Password" required>
                                <button type="submit">Sign in</button>
                            </form>
                    </body>
                </html>',
                $templateVariables['login_hint']
            );
        }

        if ('welcomePage' === $templateName) {
            return sprintf('<!DOCTYPE html>
                <html lang="en">
                    <head>
                        <meta charset="utf-8">
                        <title>Welcome</title>
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    </head>
                    <body>
                            <h2>Welcome</h2>
                            <p>Hello %s!</p>
                            <form method="post" action="_auth/form/logout?redirect_to=/">
                                <input type="submit" value="Logout">
                            </form>
                    </body>
                </html>',
                $templateVariables['user_id']
            );
        }

        return '';
    }
}
