import random
import fractions


#calculates all primes until n
def primes(n): 
	if n==2: return [2]
	elif n<2: return []
	s=range(3,n+1,2)
	mroot = n ** 0.5
	half=(n+1)/2-1
	i=0
	m=3
	while m <= mroot:
		if s[i]:
			j=(m*m-3)/2
			s[j]=0
			while j<half:
				s[j]=0
				j+=m
		i=i+1
		m=2*i+3
	return [2]+[x for x in s if x]

#print primes(3000)

#calculates coprimes of n(Euler's totient function) 
def phi(n):
    count = 0
    results=[]

    for k in range(1, n + 1):
        if fractions.gcd(n, k) == 1:
            count += 1
            results.append(k)

    return (count, results)

#print phi(7)

#calculates primitive roots module of value
def prime_root(value): 
	# `tot` gets the list of values coprime to the input, 
	# so len(tot()) is the correct totient value 
	#totient = tot(value) 
	roots = [] 
	#exp = len(totient)

	(exp, totient) = phi(value)

	for x in totient: 
		y = 1 
		while pow(x, y, value) != 1:
			# i forget exactly why i did this 
			y += 1 
			# i think it was because of the 
			if y == exp: 
				# period of the mod value 
				roots += [x] 
	return roots

#print prim_root(7)
#print primes(2000)
#print random.choice(primes(2000))
