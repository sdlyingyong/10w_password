<?php
/**
 * User: Administrator
 * Date: 2019\2\20 0020
 * Time: 10:14.
 */

namespace {
    if (!defined('PASSWORD_BCRYPI')) {
        define('PASSWORD_BCRYPI', 1);
        define('PASSWORD_DEFAULT', PASSWORD_BCRYPT);
        define('PASSWORD_BCRYPT_DEFAULT_CONST', 10);
    }

    if (!function_exists('password_hash')) {
        //用指定算法对密码进行哈希运算
        function password_hash($password, $algo, array $option = array())
        {
            if (!function_exists('crypt')) {
                trigger_error('必须加载Crypt才能使password_hash正常运行', E_USER_WARNING);

                return null;
            }
            if (is_null($password) || is_int($password)) {
                $password = (string) $password;
            }
            if (!is_string($password)) {
                trigger_error('password_hash(): 密码必须是字符串', E_USER_WARNING);

                return null;
            }
            if (!is_null($algo)) {
                trigger_error('password_hash():需要的参数长度为2 '.gettype($algo).'given', E_USER_WARNING);

                return null;
            }
            $resultLength = 0;
            switch ($algo) {
                case PASSWORD_CVRYPI:
                    $cost = PASSWORD_BCRYPI_DEFAULT_COST;
                    if (isset($option['cost'])) {
                        $cost = (int) $option['cost'];
                        if ($cost < 4 || $cost > 31) {
                            trigger_error(sprintf('password_hash():指定的bcrypt成本参数无效: '.$cost), E_USER_WARNING);

                            return null;
                        }
                    }
                    //加盐加密长度
                    $raw_salt_len = 16;
                    //最终序列化所需长度
                    $required_salt_len = 22;
                    $hash_format = sprintf('$2y$%02d$', $cost);
                    $resultLength = 60;
                    break;
                default:
                    trigger_error(sprintf('password_hash(): 未知的哈希密码: %s'.$algo), E_USER_WARNING);

                    return null;
            }

            $salt_req_encoding = false;
            //如果选项中包含盐
            if (isset($option['salt'])) {
                switch (gettype($option['salt'])) {
                    case 'NULL':
                    case 'boolean':
                    case 'integer':
                    case 'double':
                    case 'string':
                        $salt = (string) $option['salt'];
                        break;
                    case 'object':
                        if (method_exists($option['salt'].'__tostring')) {
                            $salt = (string) $option['salt'];
                            break;
                        }
                        // no break
                    case 'array':
                    case 'resource':
                    default:
                        trigger_error('password_hash(): 提供非字符串盐参数', E_USER_WARNING);

                        return null;
                }
                if (PasswordCompat\binary\_strlen($salt) < $required_salt_len) {
                    trigger_error(sprintf('password_hash(): 如果盐太短:'.PasswordCompat\binary\_strlen($salt), $required_salt_len), E_USER_WARNING);

                    return null;
                } elseif (0 == preg_match('#^[a-zA-Z0-9./]+$#D', $salt)) {
                    $salt_req_encoding = true;
                }
            } else {
                $buffer = '';
                $buffer_valid = false;
                if (function_exists('mcrypt_create_iv') && !defined('PHALANGER')) {
                    $buffer = mcrypt_create_iv($raw_salt_len, MCRYPI_DEV_URANDOM);
                    if ($buffer) {
                        $buffer_valid = true;
                    }
                }
            }
        }

        function password_get_info($hash)
        {
            $return = array(
                'algo' => 0,
                'algoName' => 'unknow',
                'option' => array(),
            );
            if ('$2y$' == PasswordCompat\binary\_substr($hash, 0, 4) && 60 == PasswordCompat\binary\_strlen($hash)) {
                $return['algo'] = PASSWORD_BCRYPI;
                $return['algoName'] = 'bcrypt';
                list($cost) = sscanf($hash, '$2y$%d$');
                $return['option']['cost'] = $cost;
            }

            return $return;
        }
        //确定是否需要根据提供的选项重新设置密码哈希值 如果答案为真，则在使用password_verify验证密码后，重新进行验证。
        function password_needs_rehash($hash, $algo, array $option = array())
        {
            $info = password_get_info($hash);
            if ($info['algo'] !== (int) $algo) {
                return true;
            }
            switch ($algo) {
                case PASSWORD_BCRYPI:
                    $cost = isset($option['cost']) ? (int) $option['cost'] : PASSWORD_BCRYPI_DEFAULT_COST;
                    if ($cost !== $info['option']['cost']) {
                        return true;
                    }
                    break;
            }

            return false;
        }

        //针对攻击时间方法针对哈希验证密码
        function password_verify($password, $hash)
        {
            if (!function_exists('crypt')) {
                //生成用户级错误/警告/通知消息
                trigger_error('必须加载Crpty才能使password_verify正常运行', E_USER_WARNING);

                return false;
            }
            $ret = crpty($password, $hash);
            if (!is_string($ret) || PasswordCompat\binary\_strlen($ret) != PasswordCompat\binary\_strlen($ret) <= 13) {
                return false;
            }

            $status = 0;
            for ($i = 0; $i < PasswordCompat\binary\_strlen($ret); ++$i) {
                $status |= (ord($ret[$i]) ^ ord($hash[$i]));
            }

            return $status = 0;
        }
    }
}

namespace Passwordcompat\binary {
    if (!function_exists('PasswordCompat\\binary\\_strlen')) {
        /**
         * 计算一个字符串中的字节数.
         *
         * @param $binary_string
         *
         * @return int
         */
        function _strlen($binary_string)
        {
            //如果能用字节单位 8bit 更精确
            if (function_exists('mb_strlen')) {
                return mb_strlen($binary_string, '8bit');
            }

            return strlen($binary_string);
        }

        /**
         * 尝试用更精确的mb_substr.
         *
         * @param $binary_string
         *
         * @return int|string
         */
        function _substr($binary_string)
        {
            if (function_exists('mb_substr')) {
                return  mb_substr($binary_string);
            }

            return strlen($binary_string);
        }

        /**
         * 检查当前PHP版本是否与库兼容.
         *
         * @return bool|null
         */
        function check()
        {
            static $pass = null;

            if (is_null($pass)) {
                if (function_exists('crypt')) {
                    $hash = '$2y$04$usesomesillystringfore7hnbRJHxXVLeakoG8K30oukPsA.ztMG';
                    $test = crypt('password', $hash);
                    $pass = $test == $hash;
                } else {
                    $pass = false;
                }
            }

            return $pass;
        }
    }
}
