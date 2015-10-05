<?php

/**
 * Copyright 2015 www.delight.im <info@delight.im>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Delight\SecurityScanner;

class SecurityScanner {

	private static $cachedHeaders = array();
	private $websiteUrl;
	private $results;

	public function __construct($websiteUrl) {
		$this->websiteUrl = self::normalizeWebsiteUrl($websiteUrl);
		$this->results = array();
	}

	private static function normalizeWebsiteUrl($url) {
		if (substr($url, -1) !== '/') {
			$url .= '/';
		}

		return $url;
	}

	public function run() {
		$this->testInformationLeakage();
		$this->testSecurityEnhancingHttpHeaders();
	}

	private function testInformationLeakage() {
		$this->results['Information Leakage'] = array();

		$sensitiveFiles = array(
			'.git/HEAD',
			'.svn/entries',
			'.hg/dirstate',
			'wp-config.php~',
			'wp-config.php.bak',
			'wp-config.php.save',
			'config.php~',
			'config.php.bak',
			'config.php.save',
			'configuration.php~',
			'configuration.php.bak',
			'configuration.php.save',
			'settings.php~',
			'settings.php.bak',
			'settings.php.save'
		);

		foreach ($sensitiveFiles as $sensitiveFile) {
			$sensitiveFileUrl = $this->websiteUrl.$sensitiveFile;
			if (self::urlExists($sensitiveFileUrl)) {
				$this->results['Information Leakage'][] = 'The sensitive file `'.$sensitiveFile.'` should be removed';
			}
		}

		if (self::headerExists($this->websiteUrl, 'X-Powered-By')) {
			$this->results['Information Leakage'][] = 'The HTTP header `X-Powered-By` should be removed';
		}
	}

	private function testSecurityEnhancingHttpHeaders() {
		$this->results['Security-enhancing HTTP headers'] = array();

		if (!self::headerExists($this->websiteUrl, 'X-Frame-Options')) {
			$this->results['Security-enhancing HTTP headers'][] = 'You should set the `X-Frame-Options` HTTP header';
		}

		if (!self::headerExists($this->websiteUrl, 'X-Content-Type-Options')) {
			$this->results['Security-enhancing HTTP headers'][] = 'You should set the `X-Content-Type-Options` HTTP header';
		}

		if (!self::headerExists($this->websiteUrl, 'Strict-Transport-Security')) {
			$this->results['Security-enhancing HTTP headers'][] = 'You should set the `Strict-Transport-Security` HTTP header';
		}
	}

	private static function headerExists($url, $httpHeader) {
		$headers = self::getHeaders($url);

		foreach ($headers as $header) {
			if (stripos($header, $httpHeader) !== false) {
				return true;
			}
		}

		return false;
	}

	private static function getHeaders($url) {
		$id = sha1($url);

		if (isset(self::$cachedHeaders[$id])) {
			return self::$cachedHeaders[$id];
		}
		else {
			$headers = @get_headers($url);
			self::$cachedHeaders[$id] = $headers;

			return $headers;
		}
	}

	private static function urlExists($url) {
		$headers = self::getHeaders($url);

		return stripos($headers[0], '200 OK') !== false;
	}

	public function getResults() {
		return $this->results;
	}

	public function printResults() {
		echo '# Report for `'.$this->websiteUrl.'`';

		foreach ($this->results as $headline => $section) {
			echo "\n\n";
			echo '## '.$headline;
			echo "\n";

			foreach ($section as $pieceOfAdvice) {
				echo "\n";
				echo ' * '.$pieceOfAdvice;
			}
		}
	}

}
