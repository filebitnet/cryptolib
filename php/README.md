## Get Upload Server
```php
require_once "filebit.php";
$CApi = new Filebit\CApi();
$ServerResponse = $CApi->Call('storage/server.json');
var_dump($ServerResponse);
```

## Get File Informations
```php
require_once "filebit.php";
$CApi = new Filebit\CApi();
$CCrypto = new Filebit\Crypto\CCrypto;
$Response = $CApi->Call('storage/bucket/info.json', array("file" => "teBKKQ6"));
$EncryptedName = $Response->filename;

$Key = 'Abts8F6i70LmwgoeUrDe_8RWMmuXBtQj5C_BguRzJL-p';
$DecryptedKeys = $CCrypto->unmergeKeyIv(Filebit\CBase64::decode($Key));
$DecryptedName = $CCrypto->decrypt(Filebit\CBase64::decode($EncryptedName), Filebit\CBase64::decode($DecryptedKeys['key']), Filebit\CBase64::decode($DecryptedKeys['iv']));

echo $DecryptedName . " Filesize: " . Filebit\Utils\formatSize($Response->filesize) . PHP_EOL;
//Example.zip Filesize: 101.23 MiB
```


## FileUpload
```bash
php upload.php PATH_TO_FILE
```