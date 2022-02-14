<?php
namespace Filebit;

class CSha256 {
	function pack($data) {
		return hash('sha256', $data);
	}

	function packFile($path) {
		return hash_file('sha256', $path);
	}
}