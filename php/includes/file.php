<?php
namespace Filebit;

class CFile {
	private $isOpen = false;
	function open($filepath) {
		$this->isOpen = true;
		$this->path = $filepath;
		$this->handle = fopen($this->path, 'r');
	}

	function close() {
		fclose($this->handle);
		$this->isOpen = false;
	}

	function size() {
		return filesize($this->path);
	}

	function read($offsetA, $offsetB) {
		if (!$this->isOpen) {
			throw new \Exception('no file open for reading');
		}
		$length = $offsetB - $offsetA;
		fseek($this->handle, $offsetA);
		//echo "Seek: " . $offsetA . PHP_EOL;
		//echo "Position of ftell: " . ftell($this->handle) . PHP_EOL;
		$buf = fread($this->handle, $length);
		fseek($this->handle, 0);
		return $buf;
	}
}