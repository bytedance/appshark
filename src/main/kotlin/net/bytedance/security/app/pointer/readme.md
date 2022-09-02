All possible statement types that taint propagates in Java:

1. local to local
   dst=src+b  
   src=dst
2. local to object field
   o.dst=src
3. local to param
   o.f(src,arg2,arg3)
4. local to this
   dst=o.f()
   
5. object field to local
   dst=o.src
6. static field to local
   dst=Object.src
7. local to static field
   Object.dst=src
