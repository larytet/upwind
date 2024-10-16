# upwind

```
// Write Network Observatility utility using BFP program.
// The utility will report every 60 seconds summary of all
// network flows and amount of bytes per flow that happened
// during that time. Flow Format:
// X.X.X.X:<Port> - Y.Y.Y.Y:<Port> Bytes: <Total Bytes>


// Hash Map Helpers

/*
 * create a bpf hash map
 */
#define BPF_HASH(_name, _key_type, _value_type, _max_entries)
/*
 * bpf_map_lookup_elem
 *
 * 	Perform a lookup in *map* for an entry associated to *key*.
 *
 * Returns
 * 	Map value associated to *key*, or **NULL** if no entry was
 * 	found.
 */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

/*
 * bpf_map_update_elem
 *
 * 	Add or update the value of the entry associated to *key* in
 * 	*map* with *value*.
 *
 * Returns
 * 	0 on success, or a negative error in case of failure.
 */
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value) = (void *) 2;

/*
 * bpf_map_delete_elem
 *
 * 	Delete entry with *key* from *map*.
 *
 * Returns
 * 	0 on success, or a negative error in case of failure.
 */
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;

/*
 *	Description
 *		Look up an element by key in a specified map and return the key
 *		of the next element. Can be used to iterate over all elements
 *		in the map.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 *		The following cases can be used to iterate over all elements of
 *		the map:
 *
 *		* If *key* is not found, the operation returns zero and sets
 *		  the *next_key* pointer to the key of the first element.
 *		* If *key* is found, the operation returns zero and sets the
 *		  *next_key* pointer to the key of the next element.
 *		* If *key* is the last element, returns -1 and *errno* is set
 *		  to **ENOENT**.
 */
static int bpf_map_get_next_key(void *map, const void *cur_key, void *next_key);


/* BPF Code - Kernel Context */

struct __sk_buff {
	__u32 len;
	__be32 remote_ip4;
	__be32 local_ip4;
	__be32 remote_port;
	__be32 local_port;
};

struct __key {
	__be32 remote_ip4;
	__be32 local_ip4;
	__be32 remote_port;
	__be32 local_port;
}

// declare a hastable "flowmap"
const u64 MAX_ENTRIES_PER_IFC = 64*1024;
typedef valueType u64;
BPF_HASH(flowmap, __key, valueType, &MAX_ENTRIES_PER_IFC);

SEC("tc")
int network_monitor(struct __sk_buff *skb)
{
      // constuct the key
      strcut key __key = {
        .remote_ip4 = skb->remote_ip4,
        .local_ip4 = skb->local_ip4,
        .remote_port = skb->remote_port,
        .local_port = skb->local_port,
      }

      valueType bytesCounter = 0
      // loookup for key, add the key if missing
      int *valueRef = bpf_map_lookup_elem(flow_map, &__key)
      if (valueRef != NULL) {
        // the key is already there 
        *valueRef = bytesCounter + skb->len;
      } else {
      	bpf_map_update_elem(flow_map, &__key, &bytesCounter);
      }
      // update the stats: sum of the packets length
  }


// Userspace Program

void printIP4DotNotation(__be32 val) {
  for (int i = 0;i<4;i++) {
    int shift = 8*(3-i)
    print("%02d", val >> shift & 0xFF);
    if i < 3 {
    	print(".");
    }
  }
}

static reportStats(void *map) {
    struct __key *cur_key = NULL;
  	struct __key next_key;
    for (;;) {
		int res = bpf_map_get_next_key(map, cur_key, &next_key);
        if (res == 0) && (next_key != dummyKey) { // found and not the first round
          	valueType *len = (*valueType)bpf_map_lookup_elem(map, &next_key);
			printf("remote_ip4=%x, len=%d\n", next_key->remote_ip4, *len);
            cur_key = &next_key;
        }
      	if (res == -1) {
          break;
        }
    }
}

int main() {
  /* 
   * 
   * eBPF initialization
   * 
   * */
  
  // Create a map "flow_map"

  
  // start here
  const int REPORT_PERIOD = 60*1000; //ms
  for (;;) {
    sleep(REPORT_PERIOD);
    reportStats(flowMap);
  }

  

  /*
   * 
   * eBPF shutdown
   * 
   * */
  
  return 0;
}
```

This what ChatGPT has to say 

```
General Observations
There are several typos and syntax issues that would cause the code not to compile.
Some conceptual issues and missing parts of the implementation are also present.
Deficiencies in Detail
Typo in the BPF_HASH Declaration:

&MAX_ENTRIES_PER_IFC should be just MAX_ENTRIES_PER_IFC because it's a constant.
The type valueType is used but not defined properly.
Fix: Define valueType as u64 before using it.

typedef u64 valueType;
BPF_HASH(flowmap, __key, valueType, MAX_ENTRIES_PER_IFC);
Typo in the network_monitor Function:

There are multiple syntax issues:
strcut should be struct.
Missing semicolon after the struct key definition.
Incorrect use of __key instead of key in the lookup and update functions.
Missing initialization of bytesCounter.
Incorrect function signature for bpf_map_lookup_elem (flow_map should be flowmap).
Fix:

struct __key key = {
  .remote_ip4 = skb->remote_ip4,
  .local_ip4 = skb->local_ip4,
  .remote_port = skb->remote_port,
  .local_port = skb->local_port,
};

u64 bytesCounter = skb->len;
int *valueRef = bpf_map_lookup_elem(flowmap, &key);
if (valueRef != NULL) {
  *valueRef += bytesCounter;
} else {
  bpf_map_update_elem(flowmap, &key, &bytesCounter, BPF_ANY);
}
Missing SEC macro definition:

The SEC macro is used to define BPF sections but not included in the code. This is essential in eBPF programs.
Fix: Ensure you include the necessary headers for BPF.

Issue with the printIP4DotNotation Function:

The if condition lacks proper syntax (if i < 3 should be if (i < 3)).
print() is not a valid function in C. Use printf() instead.
Fix:

void printIP4DotNotation(__be32 val) {
  for (int i = 0; i < 4; i++) {
    int shift = 8 * (3 - i);
    printf("%02d", (val >> shift) & 0xFF);
    if (i < 3) {
      printf(".");
    }
  }
}
Typo in reportStats:

valueType *len = (*valueType)bpf_map_lookup_elem(map, &next_key); should not have (*valueType).
You cannot directly cast the result of bpf_map_lookup_elem to valueType * like this.
The condition if (res == 0) && (next_key != dummyKey) is invalid because next_key is a struct and dummyKey is not defined.
You should use bpf_map_lookup_elem to get values and check the return status, not directly cast values.
Fix:

static void reportStats(void *map) {
  struct __key cur_key = {0};  // Dummy key to start iteration
  struct __key next_key;
  while (bpf_map_get_next_key(map, &cur_key, &next_key) == 0) {
    valueType *len = bpf_map_lookup_elem(map, &next_key);
    if (len != NULL) {
      printf("Flow: ");
      printIP4DotNotation(next_key.remote_ip4);
      printf(":%d -> ", next_key.local_port);
      printIP4DotNotation(next_key.local_ip4);
      printf(":%d Bytes: %llu\n", next_key.remote_port, *len);
    }
    cur_key = next_key;
  }
}
Error Handling in bpf_map_get_next_key:

There is no need for (next_key != dummyKey) in the for loop since the iteration will break when there are no more elements (res == -1).
Missing bpf_map_update_elem Flags:

When updating a BPF map, you should use a flag (e.g., BPF_ANY) to define how the update should happen.
Fix: Add BPF_ANY flag to bpf_map_update_elem.

bpf_map_update_elem(flowmap, &key, &bytesCounter, BPF_ANY);
Userspace Program - Missing BPF Map Initialization:

The userspace program lacks initialization of the BPF hash map (flow_map). The map must be created with the appropriate system calls, such as bpf_create_map.
Infinite Loop in main:

The loop in main lacks proper shutdown handling (it runs indefinitely without exit conditions or cleanup).
Missing Function Return Types:

reportStats and printIP4DotNotation functions are missing their return types. In C, these should be void.
Using Global Variables Without Declaration:

flowMap is used in the userspace program but is neither initialized nor defined.
Fix: The BPF map creation process should be added in the userspace side using bpf_create_map.

Conclusion:
The provided answer has several syntax, conceptual, and logical issues. Most of these issues relate to the correct use of BPF helper functions, initialization of BPF maps, and error handling. Additionally, the answer lacks proper eBPF section macros, userspace handling of BPF maps, and handling of bytes count correctly.
```


Followup quesitons:

* If a local IP interface sends a packet to another local IP intereface how many times the probe will fire. Teh answer is probably two times (ingress AND egress) per interafce.
* How to avoid double counting?
* Race in the `*valueRef += bytesCounter + skb->len;` requires an atomic
* print IPv4 dot notation. Network order? Probaly I could do `ntohl` before running a loop. I could also do something like ```void printIP4DotNotation(__be32 ip) {
    char str[INET_ADDRSTRLEN];  // INET_ADDRSTRLEN is 16, sufficient for IPv4 dotted string
    if (inet_ntop(AF_INET, &ip, str, INET_ADDRSTRLEN) != NULL) {
        printf("%s\n", str);
    } else {
        perror("inet_ntop");
    }
}```

