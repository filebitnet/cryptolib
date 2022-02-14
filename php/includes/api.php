<?php
namespace Filebit;
function progress($clientp, $dltotal, $dlnow, $ultotal, $ulnow) {
	echo "$clientp, $dltotal, $dlnow, $ultotal, $ulnow";
	return (0);
}
class CApi {
	private $endpoint = 'https://filebit.net/';
	private $fqdn = 'https://filebit.net/';
	private $ssl = true;
	function __constructor() {}

	function getURL() {
		return $this->fqdn;
	}

	private function _get($url) {
		$ch = \curl_init($url);
		\curl_setopt($ch, \CURLOPT_RETURNTRANSFER, true);
		\curl_setopt($ch, \CURLOPT_HEADER, false);
		\curl_setopt($ch, \CURLOPT_USERAGENT, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3831.6 Safari/537.36");
		$response = \curl_exec($ch);
		\curl_close($ch);
		return json_decode($response);
	}

	private function _post($url, array $params) {
		$query = \http_build_query($params);
		$ch = \curl_init();
		\curl_setopt($ch, \CURLOPT_RETURNTRANSFER, true);
		\curl_setopt($ch, \CURLOPT_HEADER, false);
		\curl_setopt($ch, \CURLOPT_URL, $url);
		\curl_setopt($ch, \CURLOPT_POST, true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($params));
		curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json'));
		//\curl_setopt($ch, \CURLOPT_POSTFIELDS, $query);
		\curl_setopt($ch, \CURLOPT_USERAGENT, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3831.6 Safari/537.36");
		$response = \curl_exec($ch);
		\curl_close($ch);
		return json_decode($response);
	}

	public function upload($server, $upload_id, $chunk_id, $offset, $buffer, $parent) {

		$tempfile = tempnam("/tmp", "dat");
		file_put_contents($tempfile, $buffer);

		$cf = new \CURLFile($tempfile);
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, (($this->ssl) ? 'https' : 'http') . '://' . $server . '/storage/bucket/' . $upload_id . '/add/' . $chunk_id . '/' . $offset[0] . '-' . $offset[1]);
		curl_setopt($ch, CURLOPT_POST, true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, ["file" => $cf]);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_NOPROGRESS, false);
		curl_setopt($ch, CURLOPT_PROGRESSFUNCTION, array($parent, '__progress'));
		$result = curl_exec($ch);
		curl_close($ch);

		unlink($tempfile);

		return json_decode($result);

	}

	public function Call(string $endpoint, array $postData = array()) {
		$url = $this->endpoint . $endpoint;
		if (count($postData) > 0) {
			return $this->_post($url, $postData);
		}
		return $this->_get($url);
	}
}