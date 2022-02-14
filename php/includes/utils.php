<?php
namespace Filebit\Utils;
function formatSize($bytes) {
	$tresh = 1024;
	if (abs($bytes) < $tresh) {
		return $bytes . ' B';
	}
	$units = array('KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB');
	$u = -1;
	do {
		$bytes /= $tresh;
		++$u;
	} while (abs($bytes) >= $tresh && $u < (count($units) - 1));
	$temp = explode(".", $bytes);
	if ($temp[1] == 0) {
		return $temp[0] . ' ' . $units[$u];
	}
	return round($bytes, 2) . ' ' . $units[$u];
}