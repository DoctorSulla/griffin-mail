<script lang="ts">
	let {
		value = $bindable(''),
		emails = [],
		id,
		placeholder = 'User email',
		required = false,
		ariaLabel,
		wrapperClass = '',
		inputClass = 'w-full rounded-md border border-gray-300 px-3 py-2'
	}: {
		value?: string;
		emails?: string[];
		id?: string;
		placeholder?: string;
		required?: boolean;
		ariaLabel?: string;
		wrapperClass?: string;
		inputClass?: string;
	} = $props();

	const uid = $props.id();
	const listboxId = `${uid}-listbox`;

	let open = $state(false);
	let highlightedIndex = $state(-1);

	let filteredEmails = $derived.by(() => {
		const query = value.trim().toLowerCase();
		if (!query) return emails;
		return emails.filter((email) => email.toLowerCase().includes(query));
	});

	let showDropdown = $derived(open && filteredEmails.length > 0);

	function select(email: string) {
		value = email;
		open = false;
		highlightedIndex = -1;
	}

	function handleInput() {
		open = true;
		highlightedIndex = -1;
	}

	function handleKeydown(event: KeyboardEvent) {
		if (!showDropdown) {
			if (event.key === 'ArrowDown' && filteredEmails.length > 0) {
				open = true;
				highlightedIndex = 0;
				event.preventDefault();
			}
			return;
		}

		if (event.key === 'ArrowDown') {
			event.preventDefault();
			highlightedIndex = (highlightedIndex + 1) % filteredEmails.length;
		} else if (event.key === 'ArrowUp') {
			event.preventDefault();
			highlightedIndex =
				highlightedIndex <= 0 ? filteredEmails.length - 1 : highlightedIndex - 1;
		} else if (event.key === 'Enter' && highlightedIndex >= 0) {
			event.preventDefault();
			select(filteredEmails[highlightedIndex]);
		} else if (event.key === 'Escape') {
			open = false;
			highlightedIndex = -1;
		}
	}
</script>

<div class="relative {wrapperClass}">
	<input
		{id}
		type="text"
		{required}
		{placeholder}
		aria-label={ariaLabel}
		autocomplete="off"
		autocapitalize="none"
		spellcheck="false"
		data-1p-ignore
		data-lpignore="true"
		data-bwignore="true"
		data-protonpass-ignore="true"
		data-form-type="other"
		role="combobox"
		aria-autocomplete="list"
		aria-controls={listboxId}
		aria-expanded={showDropdown}
		bind:value
		onfocus={() => (open = true)}
		onblur={() => {
			open = false;
			highlightedIndex = -1;
		}}
		oninput={handleInput}
		onkeydown={handleKeydown}
		class={inputClass}
	/>
	{#if showDropdown}
		<ul
			id={listboxId}
			role="listbox"
			class="absolute z-20 mt-1 max-h-56 w-full divide-y divide-gray-100 overflow-y-auto rounded-md border border-gray-200 bg-white shadow-lg"
		>
			{#each filteredEmails as email, index (email)}
				<li role="option" aria-selected={index === highlightedIndex}>
					<button
						type="button"
						onmousedown={(event) => {
							event.preventDefault();
							select(email);
						}}
						onmouseenter={() => (highlightedIndex = index)}
						class="block w-full truncate px-3 py-2 text-left text-sm {index === highlightedIndex
							? 'bg-blue-50 text-blue-700'
							: 'text-gray-900 hover:bg-gray-50'}"
					>
						{email}
					</button>
				</li>
			{/each}
		</ul>
	{/if}
</div>
