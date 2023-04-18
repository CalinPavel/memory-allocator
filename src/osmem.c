// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "helpers.h"

struct block_meta *tail_brk = NULL;
struct block_meta *head_brk = NULL;

bool prealloc = 1;

void coalesce(){

	struct block_meta *brk_address = tail_brk;
		if(brk_address != NULL){
			while(brk_address->next != NULL){
				if(brk_address->status == STATUS_FREE){
					
					struct block_meta *next_block = brk_address->next;

					if(next_block->status == STATUS_FREE){
						brk_address->size += sizeof(struct block_meta) + next_block->size;
						brk_address->next=next_block->next;
						brk_address = tail_brk;
					}
				}
					brk_address=brk_address->next;
			}
		}
}

struct block_meta *get_free_block(size_t size){

	coalesce();
	struct block_meta *brk_address = tail_brk;

		void *p=NULL;
		size_t fitted_best = INT_MAX;
	
		if(brk_address != NULL){
			while(brk_address->next != NULL){
				if(brk_address->status == STATUS_FREE){
					if((int)(brk_address->size - size) >= 0){
						if(brk_address->size - size < fitted_best){
							fitted_best = brk_address->size - size;
							p=brk_address;
						}
					}
				}
					brk_address=brk_address->next;
			}
		}

		if(brk_address->status == STATUS_FREE){
					if(brk_address->size - size < fitted_best && (int)(brk_address->size - size) >= 0){
						p=brk_address;
						fitted_best = brk_address->size - size;
					}
					if(fitted_best == INT_MAX){
						p=brk_address;
					}
		}
		if(p!=NULL){
			return p;
		}

		return NULL;
}

void *split_block(struct block_meta* check ,size_t size){
				void *return_address = (void *) check + sizeof(struct block_meta);
				
				void *p = (void*) check + sizeof(struct block_meta) + size;
				struct block_meta *second = (struct my_struct*)p;

				second->size= check->size - size - sizeof(struct block_meta);
				second->status=STATUS_FREE;
				if(check->next != NULL){
				second->next=check->next;
				}
				else
				{
					second->next=NULL;
				}

				check->status=STATUS_ALLOC;
				check->size=size;
				check->next=second;

				return return_address;
}

void *add_mmamp_node(size_t size){
			size = (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
			size = size + sizeof(struct block_meta);

			void *mem;
			mem = mmap(0, size, PROT_READ|PROT_WRITE,MAP_PRIVATE| MAP_ANONYMOUS, -1, 0);

			struct block_meta *ptr = (struct my_struct*) mem;

			ptr->next=NULL;
			ptr->status=STATUS_MAPPED;
			ptr->size=size;

		return mem + sizeof(struct block_meta);
}

void *add_head_node(size_t size){
				size = size + sizeof(struct block_meta);

				void *keep = sbrk(0) + sizeof(struct block_meta);
				void *mem = sbrk(size);

					struct block_meta *ptr = (struct my_struct*) mem;

					ptr->next=NULL;
					ptr->status=STATUS_ALLOC;
					ptr->size=size - sizeof(struct block_meta);

					if(tail_brk == NULL){
						tail_brk=ptr;
						head_brk=ptr;
					}
					else{
						struct block_meta *node = tail_brk;
						while(node->next != NULL){
							node=node->next;
						}
					node->next=mem;
					head_brk=mem;
					}
			return keep;
}

void *add_brk_node(size_t size){
		struct block_meta *check = get_free_block((size + ALIGNMENT - 1) & ~(ALIGNMENT - 1));

		size = (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);


		if(check == NULL){
			size = (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
			add_head_node(size);

		}else
		{
			size = (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);

			if(check->size == size){
				check->status=STATUS_ALLOC;

				void *return_address = (void *) check + sizeof(struct block_meta);
				return return_address;
			}

			if(check->size > size){
				void *return_address = (void *) check + sizeof(struct block_meta);

				if(check->size >= size + sizeof(struct block_meta) + 8){
					return split_block(check,size);
				}

				check->status=STATUS_ALLOC;

				return return_address;

			}

			//reuse block
			if(check->size < size && check->next == NULL){
				sbrk(size-check->size);

				struct block_meta *ptr = (struct my_struct*) check;

				ptr->next=NULL;
				ptr->status=STATUS_ALLOC;
				ptr->size=size;

				void *return_address = (void *) check;
				return return_address + sizeof(struct block_meta);
			}
			else
			{
				//add new block
				add_head_node(size);
			}
		}
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	if(size == 0){
		return NULL;
	}

	//use brk
	if(size < MMAP_THRESHOLD){

		if(size < PREALLOC && prealloc == 1){
			size=PREALLOC;
			prealloc = 0;

			void *keep = sbrk(0) + sizeof(struct block_meta);
			void *mem = sbrk(size);

			struct block_meta *ptr = (struct my_struct*) mem;

			ptr->next=NULL;
			ptr->status=STATUS_ALLOC;
			ptr->size=size;

			tail_brk=mem;
			head_brk=mem;

			return keep;
		}

		if(size < PREALLOC && prealloc == 0){
			return add_brk_node(size);
		}
	}

	//add mmap zone
	if(size >= MMAP_THRESHOLD){
			return add_mmamp_node(size);
	}
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	void *p = ptr;
	p -= sizeof(struct block_meta);

	if(ptr == NULL)
		return ;

	//mark as free
	if(tail_brk != NULL){
		struct block_meta *node = tail_brk;

			while(node->next != NULL && tail_brk != NULL){
				if(node == p){
					node->status=STATUS_FREE;
					break;
				}
				node=node->next;
			}
				if(node == p)
					node->status=STATUS_FREE;
	}

	struct block_meta *mmap_address = (struct my_struct*) p;

	//delete mmap zones
	if(mmap_address->status == STATUS_MAPPED){
		munmap(p, mmap_address->size);
	}


}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	if(nmemb == 0 || size == 0){
		return NULL;
	}

	// size = (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);

	size_t total_size;
	total_size = nmemb*size;

	if(total_size + sizeof(struct block_meta) < PAGE_SIZE){

		if(total_size  + sizeof(struct block_meta) < PAGE_SIZE && prealloc == 1){
			size=PREALLOC;
			prealloc = 0;

			void *keep = sbrk(0) + sizeof(struct block_meta);
			void *mem = sbrk(size);

			struct block_meta *ptr = (struct my_struct*) mem;

			ptr->next=NULL;
			ptr->status=STATUS_ALLOC;
			ptr->size=size;

			tail_brk=mem;
			head_brk=mem;
			return keep;
		}

		if(total_size  + sizeof(struct block_meta) < PAGE_SIZE && prealloc == 0){
			void *p = add_brk_node(total_size);
			memset(p,0,total_size);
			return p;
		}
	}


	if(total_size + sizeof(struct block_meta) >= PAGE_SIZE){
		void *p = add_mmamp_node(total_size);
		memset(p,0,total_size);
		return p;
	}

}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */

	if(ptr == NULL && size == NULL)
		return NULL;

	if(ptr != NULL){
		struct block_meta *data = (struct my_struct*)(ptr - sizeof(struct block_meta));	
		if(data->status == STATUS_FREE){
			return NULL;
		}
	}
	

	if(ptr == NULL){
		void *p = os_malloc(size);
		return p;
	}

	struct block_meta *data = (struct my_struct*)(ptr - sizeof(struct block_meta));	

	if(size == 0){
		os_free(ptr);
		return NULL;
	}


	if(data->status == STATUS_FREE){
		return NULL;
	}

	if(data->size == size){ 
		return ptr;
	}

	if(data->size > MMAP_THRESHOLD && size < MMAP_THRESHOLD){
		void *p = os_malloc(size);
		memcpy(p,ptr,size);
		os_free(ptr);
		return p;
	}
	
	if(data->size < MMAP_THRESHOLD && size < MMAP_THRESHOLD && data->size >= size + sizeof(struct block_meta) + 8){
		split_block(data,size);
		return ptr;
	}

	if(data->size < MMAP_THRESHOLD && size < MMAP_THRESHOLD && data->size > size){
		return ptr;
	}

	if(data->size < MMAP_THRESHOLD && size > MMAP_THRESHOLD && data->size < size){
		void *p = os_malloc(size);
		memcpy(p,ptr,data->size);
		os_free(ptr);
		return p;
	}

	if(data->size > MMAP_THRESHOLD && size > MMAP_THRESHOLD){
		void *p = os_malloc(size);
		memcpy(p,ptr,size);
		os_free(ptr);
		return p;
	}

	if(data->size < size && size <= MMAP_THRESHOLD){

		// size = (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);

		size_t keep = data->size;
		void *p1 = data->next;

		struct block_meta *brk_address = data;
		struct block_meta *next_block = data->next;

		if(brk_address != NULL){
			while(brk_address->next != NULL){					
					struct block_meta *next_block = brk_address->next;

					if(next_block->status == STATUS_FREE){
						data->size += sizeof(struct block_meta) + next_block->size;
						data->next=next_block->next;
						data = data;
					}

					if(data->size >= size+24){
						return ptr;
					}
					brk_address=brk_address->next;
			}
		}

		data->status=STATUS_FREE;
		data->next=p1;
		data->size=keep;
		
		void *p = os_malloc(size);

		memcpy(p,ptr,keep);
		os_free(ptr);

		struct block_meta *data = (struct my_struct*)(p - sizeof(struct block_meta));
		data->status=STATUS_ALLOC;
		return  p;
	}

	return NULL;

}
