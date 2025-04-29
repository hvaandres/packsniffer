rule UPX_Packed
{
    meta:
        description = "Detects UPX-packed files"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
    condition:
        $upx0 and $upx1
}
