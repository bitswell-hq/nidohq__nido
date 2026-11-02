/**
 * How many open recovery attempts count as many (`docs/email-recovery/spec.md`
 * §10, §10.2). Opening an attempt is permissionless, so many of them open at
 * once can be someone hiding the one that matters among them: above this
 * number the alert vault sends a required alert and the wallet shows a
 * warning above the attempts it lists.
 */
export const MANY_OPEN_ATTEMPTS = 8;
