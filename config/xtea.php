<?php defined('SYSPATH') or die('No direct script access.');

return array(
	'default' => array(
		/**
		 * The following options must be set:
		 *
		 * string   key     secret passphrase
		 * integer  mode    encryption mode, one of MCRYPT_MODE_CBC or MCRYPT_MODE_ECB
		 */
		'key' => '59a21150080313e1c2f4cbfd835b5748',
		'mode'   => MCRYPT_MODE_CBC,
	),

);
