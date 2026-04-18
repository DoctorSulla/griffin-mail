<script>
	import CircleX from '@lucide/svelte/icons/circle-x';
	import CirclePlus from '@lucide/svelte/icons/circle-plus';

	let recipients = $state([{ name: '', email: '' }]);

	function submitRecipients() {
		console.log($state.snapshot(recipients));
	}
</script>

<form onsubmit={submitRecipients}>
	{#each recipients as recipient, index (recipient)}
		<div>
			<input
				class="my-2 border border-black p-1"
				placeholder="Name"
				bind:value={recipient.name}
				type="text"
				required
			/>
			<input
				class="my-2 border border-black p-1"
				placeholder="Email"
				bind:value={recipient.email}
				type="email"
				required
			/>
			{#if index > 0}
				<CircleX
					onclick={() => recipients.splice(index, 1)}
					class="mx-2 inline cursor-pointer text-red-600 hover:text-red-700"
				/>
			{/if}
		</div>
	{/each}

	<CirclePlus
		onclick={() => recipients.push({ name: '', email: '' })}
		class="cursor-pointer text-green-600 hover:text-green-700"
	/>
	<button type="submit" class="my-2 rounded-2xl border border-black bg-blue-300 p-2"
		>Add Recipients</button
	>
</form>
