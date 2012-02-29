<?php defined('SYSPATH') or die('No direct script access.');

/* PHP Implementation of XTEA (www.php-einfach.de)
 *
 * XTEA was designed in 1997 by David Wheeler and Roger Needham
 * of the Cambridge Computer Laboratory.
 * It is not subject to any patents.
 *
 * It is a 64-bit Feistel cipher, consisting of 64 rounds.
 * XTA has a key length of 128 bits.
 *
 *
 * ***********************
 * Diese Implementierung darf frei verwendet werden, der Autor uebernimmt keine
 * Haftung fuer die Richtigkeit, Fehlerfreiheit oder die Funktionsfaehigkeit dieses Scripts.
 * Benutzung auf eigene Gefahr.
 *
 * Ueber einen Link auf www.php-einfach.de wuerden wir uns freuen.
 *
 * ************************
 * Usage:
 * <?php
 * $cipher = XTEA::instance()->encode("Hello World"); //Encrypts 'Hello World'
 * $plain = XTEA::instance()->decode($cipher); //Decrypts the cipher text
 *
 * echo $plain;
 * ?>
 */
class XTEA_Core {

	//Private
	protected $key;

    // CBC or ECB Mode
    // normaly, CBC Mode would be the right choice
	protected $mode = MCRYPT_MODE_CBC;

	/**
	 * @var  string  default instance name
	 */
	public static $default = 'default';

	/**
	 * @var  array  XTEA class instances
	 */
	public static $instances = array();

	/**
	 * Returns a singleton instance of Encrypt. An encryption key must be
	 * provided in your "encrypt" configuration file.
	 *
	 *     $encrypt = XTEA::instance();
	 *
	 * @param   string  configuration group name
	 * @return  XTEA
	 */
	public static function instance($name = NULL)
	{
		if ($name === NULL)
		{
			// Use the default instance name
			$name = XTEA::$default;
		}

		if ( ! isset(XTEA::$instances[$name]))
		{
			// Load the configuration data
			$config = Kohana::$config->load('xtea')->$name;

			if ( ! isset($config['key']))
			{
				// No default encryption key is provided!
				throw new Kohana_Exception('No encryption key is defined in the encryption configuration group: :group',
					array(':group' => $name));
			}

			if ( ! isset($config['mode']))
			{
				// Add the default mode
				$config['mode'] = MCRYPT_MODE_CBC;
			}

			// Create a new instance
			XTEA::$instances[$name] = new XTEA($config['key'], $config['mode']);
		}

		return XTEA::$instances[$name];
	}

	/**
	 * Creates a new mcrypt wrapper.
	 *
	 * @param   string   encryption key
	 * @param   string   mcrypt mode
	 * @param   string   mcrypt cipher
	 */
	public function __construct($key, $mode)
	{
		$this->key_setup($key);
		$this->mode = $mode;
	}

	//Verschluesseln
	public function encode($text)
	{
		$n = strlen($text);
		if($n%8 != 0)
		{
			$lng = ($n+(8-($n%8)));
		}
		else
		{
			$lng = 0;
		}

		$text = str_pad($text, $lng, ' ');
		$text = $this->_str2long($text);

		//Initialization vector: IV
		if($this->mode === MCRYPT_MODE_CBC)
		{
			$cipher[0][0] = time();
			$cipher[0][1] = (double)microtime()*1000000;
		}

		$a = 1;
		for($i = 0; $i<count($text); $i+=2) {
			if($this->mode === MCRYPT_MODE_CBC)
			{
				//$text mit letztem Geheimtext XOR Verknuepfen
				//$text is XORed with the previous ciphertext
				$text[$i] ^= $cipher[$a-1][0];
				$text[$i+1] ^= $cipher[$a-1][1];
			}

			$cipher[] = $this->block_encrypt($text[$i],$text[$i+1]);
			$a++;
		}

		$output = "";
		for($i = 0; $i<count($cipher); $i++)
		{
			$output .= $this->_long2str($cipher[$i][0]);
			$output .= $this->_long2str($cipher[$i][1]);
		}

		return base64_encode($output);
	}

	//Entschluesseln
	public function decode($text)
	{
		$plain = array();
		$cipher = $this->_str2long(base64_decode($text));
		
		if($this->mode === MCRYPT_MODE_CBC)
		{
			$i = 2; //Message start at second block
		}
		else
		{
			$i = 0; //Message start at first block
		}
		
		for($i; $i<count($cipher); $i+=2)
		{
			$return = $this->block_decrypt($cipher[$i],$cipher[$i+1]);

			//Xor Verknuepfung von $return und Geheimtext aus von den letzten beiden Bloecken
			//XORed $return with the previous ciphertext
			if($this->mode === MCRYPT_MODE_CBC)
			{
				$plain[] = array($return[0]^$cipher[$i-2],$return[1]^$cipher[$i-1]);
			}
			else //EBC Mode
			{
				$plain[] = $return;
			}
		}

		$output = '';
		for($i = 0; $i<count($plain); $i++)
		{
			$output .= $this->_long2str($plain[$i][0]);
			$output .= $this->_long2str($plain[$i][1]);
		}
		
		return $output;
	}

	//Bereitet den Key zum ver/entschluesseln vor
	public function key_setup($key)
	{
        if (is_array($key))
		{
          $this->key = $key;
        }
		elseif (isset($key) AND ! empty($key))
		{
            $this->key = $this->_str2long(str_pad($key, 16, $key));
        }
		else
		{
            $this->key = array(0,0,0,0);
		}
	}

    /***********************************
            Some internal functions
     ***********************************/
	protected function block_encrypt($y, $z)
	{
		$sum=0;
		$delta=0x9e3779b9;
		/* start cycle */
		
		for ($i=0; $i<32; $i++)
		{
			$y = $this->_add($y, $this->_add($z << 4 ^ $this->_rshift($z, 5), $z) ^ $this-> _add($sum, $this->key[$sum & 3]));
			$sum = $this->_add($sum, $delta);
			$z = $this->_add($z, $this->_add($y << 4 ^ $this->_rshift($y, 5), $y) ^ $this->_add($sum, $this->key[$this->_rshift($sum, 11) & 3]));
		}

		/* end cycle */
		$v[0]=$y;
		$v[1]=$z;
		
		return array($y,$z);
	}
   
   protected function block_decrypt($y, $z)
   {
		$delta=0x9e3779b9;
		$sum=0xC6EF3720;
		$n=32;
		/* start cycle */
		for ($i=0; $i<32; $i++)
		{
			$z = $this->_add($z, -($this->_add($y << 4 ^ $this->_rshift($y, 5), $y) ^ $this->_add($sum, $this->key[$this->_rshift($sum, 11) & 3])));
			$sum = $this->_add($sum, -$delta);
			$y = $this->_add($y, -($this->_add($z << 4 ^ $this->_rshift($z, 5), $z) ^ $this->_add($sum, $this->key[$sum & 3])));
		}
		/* end cycle */
		return array($y,$z);
    }

	protected function _rshift($integer, $n)
	{
        // convert to 32 bits
        if (0xffffffff < $integer || -0xffffffff > $integer)
		{
            $integer = fmod($integer, 0xffffffff + 1);
        }

        // convert to unsigned integer
        if (0x7fffffff < $integer)
		{
            $integer -= 0xffffffff + 1.0;
        } elseif (-0x80000000 > $integer)
		{
            $integer += 0xffffffff + 1.0;
        }

        // do right shift
        if (0 > $integer)
		{
            $integer &= 0x7fffffff;                     // remove sign bit before shift
            $integer >>= $n;                            // right shift
            $integer |= 1 << (31 - $n);                 // set shifted sign bit
        }
		else
		{
            $integer >>= $n;                            // use normal right shift
        }

        return $integer;
    }

    protected function _add($i1, $i2)
	{
        $result = 0.0;

        foreach (func_get_args() as $value)
		{
            // remove sign if necessary
            if (0.0 > $value)
			{
                $value -= 1.0 + 0xffffffff;
            }

            $result += $value;
        }

        // convert to 32 bits
        if (0xffffffff < $result || -0xffffffff > $result)
		{
            $result = fmod($result, 0xffffffff + 1);
        }

        // convert to signed integer
        if (0x7fffffff < $result)
		{
            $result -= 0xffffffff + 1.0;
        }
		elseif (-0x80000000 > $result)
		{
            $result += 0xffffffff + 1.0;
        }

        return $result;
    }


   //Einen Text in Longzahlen umwandeln
   //Covert a string into longinteger
   protected function _str2long($data)
   {
		$n = strlen($data);
		$tmp = unpack('N*', $data);
		$data_long = array();
		$j = 0;

		foreach ($tmp as $value)
		{
			$data_long[$j++] = $value;
		}
		return $data_long;
   }

   //Longzahlen in Text umwandeln
   //Convert a longinteger into a string
   protected function _long2str($l)
   {
       return pack('N', $l);
   }

} // XTEA_Core