<script lang="ts">
	import CircleX from '@lucide/svelte/icons/circle-x';
	import CirclePlus from '@lucide/svelte/icons/circle-plus';
	import { api, type Recipient } from '$lib/api';

	let recipients: Recipient[] = $state([{ name: '', email: '' }]);

	let response = $state({ response_type: '', message: '' });

	async function submitRecipients() {
		api.addRecipients(recipients);
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
			{#if recipients.length > 1}
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
	<button
		type="submit"
		class="my-2 rounded-xl border border-blue-400 bg-blue-300 px-4 py-2 ring-blue-300/50 hover:ring-2"
		>Add Recipients</button
	>
</form>
