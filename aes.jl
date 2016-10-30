using Nettle


hexChars = "0123456789abcdef"
function reasonable(text::Array{UInt8, 1})
  n = size(text)[1]
  p = n/5
  if n < 20
    return false
  end
  l = 0.0
  a = 0.0
  for i in 1:(n-1)
    x = text[i]
    if x< 32
      return false
    end
    if x>243
      return false
    end
    if x > 128
      if l< p
        l+=1
      else
        return false
      end
    end
    if 64 < x <123
      a+=1
    end
  end
  if a/n > 0.6
    return true
  else
    return false
  end
end

function testKeys(suffix::Array{UInt8, 1}, iv::Array{UInt8, 1}, ciphertext::Array{UInt8, 1})
  n = size(suffix)
  m = 32 - n[1]
  fullKey = cat(1,convert(Array{UInt8,1},linspace(00,00,m)),suffix)
  fullKey[m] = 0x00
  con = true
  while con
    decode(fullKey,iv,ciphertext)
    if(m == 0)
      break
    end
    #println("incr start")
    for i in 1:m
      if(i==m)
        println(fullKey[i]+1)
      end
      if(fullKey[i]!= 0xff)
        fullKey[i]+=1
        break
      else
        if(i+1==m && fullKey[m]==0x3f)
          con = false
        else
          fullKey[i] = 0x00
        end
      end
    end
  end
end

function decode(key::Array{UInt8, 1}, iv::Array{UInt8, 1}, ciphertext::Array{UInt8, 1})
  #println("dec start")
  dec = Decryptor("AES256", key)
  plaintext = trim_padding_PKCS5(decrypt(dec, :CBC, iv, ciphertext))
  if(reasonable(plaintext))
    text = String(plaintext)
    open("C:/Users/nowyd_000/Desktop/julia/aes/tmp/t1.txt", "a") do file
      write(file,text)
      write(file,"\n")
    end
  end
  #println("dec stop")
end

function findText(suffix::AbstractString, iv::Array{UInt8, 1}, ciphertext::Array{UInt8, 1})
  if length(suffix)%2 != 0
    for i in 1:16
      #println("next")
      newSuffix = hex2bytes(string(hexChars[i],suffix))
      testKeys(newSuffix,iv,ciphertext)
    end
  else
      newSuffix = hex2bytes(suffix)
      testKeys(newSuffix,iv,ciphertext)
  end
end

key = "344e0b70d500619e6a8e5169b166914bd12f5d2572ea5d907cda753"
iv = hex2bytes("526f22f46e8fa8e4aed88408b930ad06")
ciphertext = base64decode("Fd2+e+7rXHfIkrOAgfjflzsopBTjTN0tzhC9nZmrAOMFdicSDa1uGOhNCJ4szlrUOJ7FUf1Agu8xdUb1vJS91rL0tgKM/lwKYkOfB/4ouB+jXxFznKuk2nXAErITN6BBcppAXMftEeJWn4SJMStJM6wTMHOB1NcYGpGGlzO0b3ZHvCjNH7U2I8c/fT+yZyiOa7mxhlmF10T1rWhFwrvem9R2bSqnDlkSt1h78TCCCBw=")

text = findText(key,iv,ciphertext)

println("done")
