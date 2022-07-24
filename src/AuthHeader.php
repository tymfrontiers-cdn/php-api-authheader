<?php
namespace TymFrontiers\API;

class AuthHeader{
  private static $_conn;

  public static function generate (string $app, string $pu_key, string $pr_key, string $sign_meth="sha512", string $accept = "application/json", string $content_type = "application/json") {
    $sign_meth = \strtolower($sign_meth);
    $sign_meths = ["sha256","sha512"];
    if( !\in_array($sign_meth,$sign_meths) ){
      throw new \Exception("[{$sign_meth}]: not accepted for signature method! Only " . \implode(', ',$sign_meths) . " allowed.", 1);
    }
    global $database;
    if ((empty($database) || !$database instanceof \TymFrontiers\MySQLDatabase) && !self::$_conn) {
      throw new \Exception("No Database connection defned", 1);
    }
    $conn = self::$_conn ? self::$_conn : $database;
    $app_object = new DevApp($conn, $conn->getDatabase());
    if (!$app_object->load($app, $pu_key, true)) {
      throw new \Exception("Developer App '{$app}' not found.", 1);
    }
    $header = [
      "Accept" => $accept,
      "Content-Type" => $content_type,
      "Auth-App" => $app,
      "Auth-Key" => $pu_key,
      "Signature-Method" => $sign_meth
    ];
    $tym = \time();
    $hash_string = "{$app_object->prefix}&{$app}&{$pr_key}&{$sign_meth}&{$tym}";
    $header["Tymstamp"] = $tym;
    $header["Auth-Signature"] = \base64_encode(\hash($sign_meth,$hash_string));
    return $header;
  }
  public function setConnection (\TymFrontiers\MySQLDatabase $conn) {
    static::$_conn = $conn;
  }
}
