from sys import stdout
from Crypto.Util import number

# znajduje liczbe pierwsza p i generator g grupy multiplikatywnej Zp
# metoda:
# p - 1 = q1 * q2 * ... * qn
# dla kazdego 1, g nie jest generatorem jesli g ^ ((p-1) / q) mod p == 1
def find_generator_and_prime(bits, n, gen_max_bits = False):
	# p - 1 = q1 * q2 * q3 * ... * qn
	p_sub_1 = 0 # p - 1
	p = 0
	stdout.write('Trying to find prime p ')
	while(not number.isPrime(p)): # sprawdzamy czy liczba p jest pierwsza, inaczej nie ma sensu szukac generatora
		stdout.write('.')
		qs = [2] # lista q, inicjowana q1 = 2, bez 2 p+1 bylaby zawsze liczba parzysta czyli nie pierwsza
		p_sub_1 = qs[0] # p - 1 = q1
		for i in range(0, n):
			q = number.getPrime(bits/n)
			tmp_p_sub_1 = p_sub_1 * q
			tmp_p = tmp_p_sub_1 + 1
			if number.size(tmp_p) <= bits: # sprawdzamy czy liczba p ma tyle bitow ile chcemy
				p_sub_1 = tmp_p_sub_1
				p = tmp_p
				qs.append(q)
			else:
				break
		
		if(number.size(p_sub_1) != bits): # dopelniamy do oczekiwanej liczby bitow mnozac kilkukrotnie przez 2
			p_sub_1 <<= bits-number.size(p_sub_1)
			p = p_sub_1 + 1
	
	stdout.write('\n' + str(number.size(p)) + ' bits prime p found\n')

	stdout.write("Trying to find generator g ")
	while(1): # kazda grupa cykliczna ma generator
		stdout.write('.')
		
		if gen_max_bits:
			g = number.getRandomNBitInteger(bits) # generator moze miec dowolna liczbe bitow
			if g >= p:
				continue
		else:
			g = number.getRandomRange(2, p)
		
		isGenerator = True
		for q in qs:
			if pow(g, p_sub_1/q, p) == 1: # nie jest generatorem jesli g ^ ((p-1) / q) mod p == 1
				isGenerator = False
				break;
		
		if isGenerator:
			stdout.write('\n' + str(number.size(g)) + ' bits generator g found\n')
			return p, g
			
# to samo co wyzej tylko ze q1=2 q2=(p-1)/2
# p na pewno bedzie safe prime
def find_generator_and_safe_prime(bits, gen_max_bits = False):
	stdout.write('Trying to find prime p ')
	while(1):
		stdout.write('.')
		q = number.getPrime(bits-1) # zeby pomnozona przez 2 byla na pewno mniejsza od p, (+1 pomijam, zakladam ze nie przekroczy)
		p = (q << 1) + 1
		if number.isPrime(p):
			print '\n' + str(number.size(p)) + ' bits prime p found'
			p_sub_1 = p - 1
			
			stdout.write('Trying to find generator g ')
			while(1):
				if gen_max_bits: # generator moze miec dowolna liczbe bitow
					g = number.getRandomNBitInteger(bits)
					if g >= p:
						continue
				else:
					g = number.getRandomRange(2, p)
				
				if pow(g, 2, p) == 1 or pow(g, q, p) == 1:
					stdout.write('.')
					continue
					
				print '\n' + str(number.size(g)) + ' bits generator g found'
				return p, g

p,g = find_generator_and_safe_prime(1024, True)
p_file = open('PRIME.bin', 'wb')
g_file = open('GENERATOR.bin', 'wb')
p_file.write(number.long_to_bytes(p))
g_file.write(number.long_to_bytes(g))
p_file.close()
g_file.close()