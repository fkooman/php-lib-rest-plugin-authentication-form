<?php

/**
 *  Copyright 2015 François Kooman <fkooman@tuxed.net>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace fkooman\Rest\Plugin\Authentication\Form\Test;

use fkooman\Json\Json;
use fkooman\Tpl\TemplateManagerInterface;

class TestTemplateManager implements TemplateManagerInterface
{
    public function setDefault(array $templateVariables)
    {
        // NOP
    }

    public function addDefault(array $templateVariables)
    {
        // NOP
    }

    public function render($templateName, array $templateVariables = [])
    {
        return Json::encode(
            [
                $templateName => $templateVariables,
            ]
        );
    }
}
