<?php
namespace TymFrontiers\API;

class AuthHeader{

  public static function generate (DevApp $app, string $sign_meth="sha512", string $accept = "application/json", string $content_type = "application/json") {
    $sign_meth = \strtolower($sign_meth);
    $sign_meths = ["sha256","sha512"];
    if( !\in_array($sign_meth,$sign_meths) ){
      throw new \Exception("[{$sign_meth}]: not accepted for signature method! Only " . \implode(', ',$sign_meths) . " allowed.", 1);
    }
    $header = [
      "Accept" => $accept,
      "Content-Type" => $content_type,
      "Auth-App" => $app->name,
      "Auth-Key" => $app->publicKey(),
      "Signature-Method" => $sign_meth
    ];
    $tym = \time();
    $hash_string = "{$app->prefix}&{$app->name}&{$app->privateKey()}&{$sign_meth}&{$tym}";
    $header["Tymstamp"] = $tym;
    $header["Auth-Signature"] = \base64_encode(\hash($sign_meth,$hash_string));
    return $header;
  }
}
