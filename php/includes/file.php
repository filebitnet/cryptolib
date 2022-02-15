<?php
namespace Filebit;

class CFile {
	private $isOpen = false;
	function open($filepath, $handle = 'r') {
		$this->isOpen = true;
		$this->path = $filepath;
		$this->handle = fopen($this->path, $handle);
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
		$buf = fread($this->handle, $length);
		fseek($this->handle, 0);
		return $buf;
	}

	function write($start, $buf) {
		if (!$this->isOpen) {
			throw new \Exception('no file open for writing');
		}
		fseek($this->handle, $start);
		fwrite($this->handle, $buf);
		fseek($this->handle, 0);
		return true;
	}

}