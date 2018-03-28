<?php
/**
 * Class used to bypass CloudFlare browser challenge
 *
 * User: Catalina
 * Date: 1/3/18
 * Time: 12:20 PM
 */

class CloudFlareBypass
{
    private $_strFilePath;

    private $_strRedirect = '/cdn-cgi/l/chk_jschl';

    public function __construct($strFilePath = "")
    {
        $this->_strFilePath = $strFilePath;
    }

    public function _getPage($strURL, $intRetries = 3, $arrProxy = array())
    {
        $bolFound = false;
        for($intI = 0; $intI < $intRetries; $intI++)
        {
            $ch = $this->_initCurl($arrProxy);
            curl_setopt($ch,CURLOPT_URL, $strURL);

            $strResult = curl_exec($ch);
            curl_close($ch);

            if(strpos($strResult, 'jschl_vc') !== false)
            {
                $arrParams = $this->_solveJavaScriptChallenge($strURL, $strResult);
                print_r($arrParams);
                if($arrParams)
                {
                    $ch = $this->_initCurl($arrProxy);
                    curl_setopt($ch,CURLOPT_URL, $strURL.$this->_strRedirect.'?'.http_build_query($arrParams));
                    $strResult = curl_exec($ch);
                    $intResponseCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                    curl_close($ch);

                    if($intResponseCode != '200')
                    {
                        echo "!!! ERROR !!! Request failed, trying again...\n";
                        continue;
                    }

                    $bolFound = true;
                }

            }
        }

        if($bolFound)
            return $strResult;

        return false;
    }

    /**
     * Initialise cURL with proxies, cookies and user agent
     * @param array $arrProxy           Proxy array (e.g. array("IP:PORT" => "192.168.0.1", "ua" => "Chrome user agent example") )
     * @return bool|resource
     */
    private function _initCurl($arrProxy)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_AUTOREFERER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);

        $strFilePath = $this->_strFilePath;

        if($strFilePath !== '')
        {
            $strFilePath .= '/';

        }

        // Set one cookie file per proxy
        if (!file_exists($strFilePath.'cookies'))
        {
            mkdir($strFilePath.'cookies', 0777, true);
        }

        if(count($arrProxy) > 0)
        {
            // Set cookies for each proxy
            curl_setopt($ch, CURLOPT_COOKIEFILE, $strFilePath.'/cookies/cookie-'.$arrProxy['IP:PORT'].'.txt');
            curl_setopt($ch, CURLOPT_COOKIEJAR, $strFilePath.'/cookies/cookie-'.$arrProxy['IP:PORT'].'.txt');

            // Set the cURL resource according to the type of proxy
            switch(trim(strtolower($arrProxy['PROTOCOL'])))
            {
                case 'http':
                    curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
                    break;
                case 'socks':
                case 'socks5':
                    curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
                    break;
                default:
                    return false;
            }

            // Set proxy
            curl_setopt($ch, CURLOPT_PROXY, $arrProxy['IP:PORT']);

            // Set user agent
            curl_setopt($ch, CURLOPT_USERAGENT, $arrProxy['ua']);
        }
        else
        {
            curl_setopt($ch, CURLOPT_COOKIEFILE, $strFilePath.'/cookies/cookie.txt');
            curl_setopt($ch, CURLOPT_COOKIEJAR, $strFilePath.'/cookies/cookie.txt');
        }

        return $ch;
    }

    private function _solveJavaScriptChallenge($siteLink, $response){
        // sleep 4 seconds to mimic waiting process
        sleep(4);
        // get values from js verification code and pass code inputs
        $jschl_vc = $this->_getInputValue($response, 'jschl_vc');
        $pass     = $this->_getInputValue($response, 'pass');
        // extract javascript challenge code from CloudFlare script
        $siteLen = mb_strlen(substr($siteLink, strpos($siteLink,'/')+2), 'utf8');
        $script  = substr($response, strpos($response, 'var s,t,o,p,b,r,e,a,k,i,n,g,f,') + mb_strlen('var s,t,o,p,b,r,e,a,k,i,n,g,f,', 'utf8'));
        $varname = trim(substr($script, 0, strpos($script, '=')));
        $script  = substr($script, strpos($script, $varname));
        // removing form submission event
        $script  = substr($script, 0, strpos($script, 'f.submit()'));
        // structuring javascript code for PHP conversion
        $script  = str_replace(array('t.length', 'a.value'), array($siteLen, '$answer'), $script);
        $script  = str_replace(array("\n", " "), "", $script);
        $script  = str_replace(array(";;", ";"), array(";", ";\n"), $script);
        // convert challenge code variables to PHP variables
        $script  = preg_replace("/[^answe]\b(a|f|t|r)\b(.innerhtml)?=.*?;/i", '', $script);
        $script  = preg_replace("/(\w+).(\w+)(\W+)=(\W+);/i", '$$1_$2$3=$4;', $script);
        $script  = preg_replace("/(parseInt)?\((\w+).(\w+),.*?\)/", 'intval($$2_$3)', $script);
        $script  = preg_replace("/(\w+)={\"(\w+)\":(\W+)};/i", '$$1_$2=$3;', $script);
        // convert javascript array matrix in equations to binary which PHP can understand
        $script  = str_replace(array("!![]", "!+[]"), 1, $script);
        $script  = str_replace(array("![]", "[]"), 0, $script);
        $script  = str_replace(array(")+", ").$siteLen"), array(").", ")+$siteLen"), $script);
        // take out any source of javascript comment code - #JS Comment Fix
        $script  = preg_replace("/'[^']+'/", "", $script);
        // Fix
        $script  = str_replace('f.action+=location.hash;', '', $script);
        // evaluate PHP script
        eval($script);
        // if cloudflare answer has been found, store it
        if(is_numeric($answer)) {
            // return verification values
            return array(
                'jschl_vc'      => $jschl_vc,
                'pass'          => str_replace('+', '%2', $pass),
                'jschl_answer'  => $answer
            );
        }
        return false;
    }

    private function _getInputValue($response, $id)
    {
        preg_match('%'.$id.'" value="(.*?)"%s', $response, $arrMatch);
        return $arrMatch[1];
    }
}